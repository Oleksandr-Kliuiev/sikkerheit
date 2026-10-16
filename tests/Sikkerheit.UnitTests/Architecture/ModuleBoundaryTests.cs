using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Host.Data;

namespace Sikkerheit.UnitTests.Architecture;

/// <summary>
/// 02 «Структура репозитория»: a module does not use the tables of another module directly, only its interface. Modules are
/// the folders of src/Sikkerheit.Host. The test reads the sources (Roslyn syntax trees) and finds table use through the
/// DbSets of SikkerheitDb, SQL text in string literals and literal lists of table names for dynamic SQL. An access to the
/// table of another module fails unless the owner accepted it in Known (docs/dev/module-boundaries.md); an entry that no
/// longer matches an access fails too.
/// </summary>
public sealed partial class ModuleBoundaryTests
{
    /// <summary>The owner of every table of the schema (Data/Migrations).</summary>
    public static readonly IReadOnlyDictionary<string, string> Owners = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["staff_user"] = "Access", ["staff_session"] = "Access", ["staff_login"] = "Access",
        ["organization"] = "Organizations", ["policy_revision"] = "Organizations",
        ["tenant_connection"] = "M365", ["collection_run"] = "M365",
        ["subject"] = "Assessment", ["observation"] = "Assessment", ["assessment"] = "Assessment", ["finding"] = "Assessment",
        ["finding_event"] = "Assessment", ["risk_decision"] = "Assessment",
        ["report"] = "Reports", ["teams_digest"] = "Reports",
        ["organization_export"] = "Exports",
        ["job"] = "Jobs", ["organization_tombstone"] = "Jobs",
        ["audit_event"] = "Operations", ["idempotency_record"] = "Operations",
    };

    /// <summary>The schema and its access layer belong to no module; the composition root wires the modules.</summary>
    private static readonly string[] Exempt = ["Data", "Program.cs"];

    /// <summary>
    /// Module → table : file, for accesses to the tables of another module that the owner accepted, each with its reason
    /// (docs/dev/module-boundaries.md). The 67 accesses that existed when the rule got its test are gone.
    /// </summary>
    private static readonly string[] Known = [];

    public sealed record Access(string Module, string Table, string File, int Line, string How)
    {
        public string Key => $"{Module} → {Table} : {File}";

        /// <summary>The table belongs to another module.</summary>
        public bool Foreign => Owners[Table] != Module;
    }

    private static string Source => Path.Combine(RepoPaths.Root, "src", "Sikkerheit.Host");

    private static Dictionary<string, string> DbSetTables()
    {
        using var db = new SikkerheitDb(new DbContextOptionsBuilder<SikkerheitDb>().UseNpgsql("Host=unused.invalid").Options);
        return typeof(SikkerheitDb).GetProperties()
            .Where(p => p.PropertyType.IsGenericType && p.PropertyType.GetGenericTypeDefinition() == typeof(DbSet<>))
            .ToDictionary(p => p.Name, p => db.Model.FindEntityType(p.PropertyType.GetGenericArguments()[0])!.GetTableName()!,
                StringComparer.Ordinal);
    }

    private static Dictionary<string, string> EntityTables()
    {
        using var db = new SikkerheitDb(new DbContextOptionsBuilder<SikkerheitDb>().UseNpgsql("Host=unused.invalid").Options);
        return db.Model.GetEntityTypes().ToDictionary(e => e.ClrType.Name, e => e.GetTableName()!, StringComparer.Ordinal);
    }

    /// <summary>Every access of a module to a table, with the place in the source.</summary>
    public static IReadOnlyList<Access> Scan()
    {
        var dbSets = DbSetTables();
        var entities = EntityTables();
        var accesses = new List<Access>();
        foreach (var path in Directory.EnumerateFiles(Source, "*.cs", SearchOption.AllDirectories)
                     .Where(p => !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                                 && !p.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)))
        {
            var file = Path.GetRelativePath(Source, path).Replace('\\', '/');
            var module = file.Contains('/', StringComparison.Ordinal) ? file[..file.IndexOf('/', StringComparison.Ordinal)] : file;
            if (Exempt.Contains(module))
            {
                continue;
            }
            var tree = CSharpSyntaxTree.ParseText(File.ReadAllText(path), path: path);
            void Add(string table, SyntaxNode node, string how)
            {
                if (Owners.ContainsKey(table))
                {
                    accesses.Add(new Access(module, table, file, tree.GetLineSpan(node.Span).StartLinePosition.Line + 1, how));
                }
            }
            foreach (var node in tree.GetRoot().DescendantNodes())
            {
                switch (node)
                {
                    case MemberAccessExpressionSyntax member when dbSets.TryGetValue(member.Name.Identifier.Text, out var table)
                                                                  && IsContext(member.Expression):
                        Add(table, member, "DbSet " + member.Name.Identifier.Text);
                        break;
                    case GenericNameSyntax { Identifier.Text: "Set" or "Entries" } generic
                        when generic.TypeArgumentList.Arguments is [var argument]
                             && entities.TryGetValue(argument.ToString().Split('.')[^1], out var table):
                        Add(table, generic, generic.Identifier.Text + "<" + argument + ">");
                        break;
                    case LiteralExpressionSyntax literal when literal.IsKind(SyntaxKind.StringLiteralExpression):
                        foreach (var table in SqlTables(literal.Token.ValueText))
                        {
                            Add(table, literal, "SQL");
                        }
                        // A literal list of table names feeds dynamic SQL such as $"delete from {table}".
                        if (Owners.ContainsKey(literal.Token.ValueText) && InTableList(literal))
                        {
                            Add(literal.Token.ValueText, literal, "table list");
                        }
                        break;
                    case InterpolatedStringExpressionSyntax interpolated:
                        var text = string.Concat(interpolated.Contents.Select(c => c is InterpolatedStringTextSyntax t ? t.TextToken.ValueText : " {} "));
                        foreach (var table in SqlTables(text))
                        {
                            Add(table, interpolated, "SQL");
                        }
                        break;
                }
            }
        }
        return accesses;
    }

    /// <summary>scope.Db.X, all.Db.X and the SikkerheitDb field db of the finding machine.</summary>
    private static bool IsContext(ExpressionSyntax expression) => expression switch
    {
        MemberAccessExpressionSyntax { Name.Identifier.Text: "Db" } => true,
        IdentifierNameSyntax { Identifier.Text: "db" or "Db" } => true,
        _ => false,
    };

    /// <summary>
    /// An element of a collection expression or an array initializer, alone or inside a tuple: ["audit_event", …] or
    /// [("organization", "id"), …]. Keys of object initializers (["subject"] = …) and arguments are not table lists.
    /// </summary>
    private static bool InTableList(SyntaxNode literal)
    {
        var node = literal.Parent;
        while (node is ArgumentSyntax { Parent: TupleExpressionSyntax } or TupleExpressionSyntax)
        {
            node = node.Parent;
        }
        return node is ExpressionElementSyntax { Parent: CollectionExpressionSyntax }
               || node is InitializerExpressionSyntax initializer && initializer.IsKind(SyntaxKind.ArrayInitializerExpression);
    }

    private static IEnumerable<string> SqlTables(string text) =>
        SqlTable().Matches(text).Select(m => m.Groups[1].Value).Where(Owners.ContainsKey).Distinct(StringComparer.Ordinal);

    [GeneratedRegex(@"\b(?:from|join|update|into|table)\s+(?:only\s+)?([a-z_][a-z0-9_]*)", RegexOptions.IgnoreCase)]
    private static partial Regex SqlTable();

    [Fact]
    public void Every_table_of_the_schema_has_an_owner_module()
    {
        var tables = Directory.EnumerateFiles(Path.Combine(Source, "Data", "Migrations"), "*.sql")
            .SelectMany(f => CreateTable().Matches(File.ReadAllText(f)).Select(m => m.Groups[1].Value)).ToHashSet(StringComparer.Ordinal);
        Assert.Equal(tables.Order(StringComparer.Ordinal), Owners.Keys.Order(StringComparer.Ordinal));
        var modules = Directory.EnumerateDirectories(Source).Select(Path.GetFileName).ToHashSet(StringComparer.Ordinal);
        Assert.All(Owners.Values.Distinct(), owner => Assert.Contains(owner, modules));
    }

    [GeneratedRegex(@"create table (?:if not exists )?([a-z_]+)")]
    private static partial Regex CreateTable();

    [Fact]
    public void The_scan_sees_the_kinds_of_access_it_looks_for()
    {
        // A DbSet, SQL text and a table list: the scanner must find each kind, or the rule below proves nothing. The owners
        // use their own tables in all three ways, so the kinds are seen even without a single foreign access.
        var hows = Scan().Select(a => a.How.Split(' ')[0]).ToHashSet(StringComparer.Ordinal);
        Assert.Contains("DbSet", hows);
        Assert.Contains("SQL", hows);
        Assert.Contains("table", hows);
    }

    [Fact]
    public void No_module_uses_the_tables_of_another_module_beyond_the_known_list()
    {
        var found = Scan().Where(a => a.Foreign).ToList();
        var keys = found.Select(a => a.Key).ToHashSet(StringComparer.Ordinal);
        var added = found.Where(a => !Known.Contains(a.Key)).GroupBy(a => a.Key)
            .Select(g => $"{g.Key} (line {g.First().Line}, {g.First().How}): use the interface of module {Owners[g.First().Table]}")
            .ToList();
        var fixedOnes = Known.Where(k => !keys.Contains(k)).Select(k => k + ": fixed — remove it from Known").ToList();
        Assert.True(added.Count == 0 && fixedOnes.Count == 0, string.Join("\n", added.Concat(fixedOnes)));
    }
}
