namespace Sikkerheit.UnitTests;

internal static class RepoPaths
{
    public static string Root { get; } = FindRoot();

    public static string Package(params string[] parts) => Path.Combine([Root, "development-package", .. parts]);

    private static string FindRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Sikkerheit.slnx")))
        {
            directory = directory.Parent;
        }
        return directory?.FullName ?? throw new InvalidOperationException("Repository root not found");
    }
}
