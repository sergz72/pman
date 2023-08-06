using System.Diagnostics;
using System.Security;
using pman.keepass;

switch (args.Length)
{
    case 1:
        var db1 = DatabasePreLoad();
        if (db1 == null)
            return 1;
        Console.Write("Password: ");
        var password = ReadPassword();
        return Start(db1, password);
    case 2:
        var db2 = DatabasePreLoad();
        if (db2 == null)
            return 1;
        var securePassword = new SecureString();
        foreach (var c in args[1])
            securePassword.AppendChar(c);
        return Start(db2, securePassword);
    default:
        Console.WriteLine("Usage: pman db_name [password]");
        return 1;
}

KeePassDb? DatabasePreLoad()
{
    Console.WriteLine("Opening database file {0}...", args[0]);
    Stopwatch stopWatch = new Stopwatch();
    stopWatch.Start();
    try
    {
        var database = new KeePassDb(args[0]);
        Console.WriteLine("Database loaded in {0} ms", stopWatch.ElapsedMilliseconds);
        database.PrintUnencryptedDbInfo(Console.Out);
        return database;
    }
    catch (Exception e)
    {
        Console.WriteLine("Database load failed in {0} ms with error {1}", stopWatch.ElapsedMilliseconds, e.Message);
        return null;
    }
}

int Start(KeePassDb database, SecureString password)
{
    password.MakeReadOnly();
    Stopwatch stopWatch = new Stopwatch();
    stopWatch.Start();
    try
    {
        database.Decrypt(password, null);
        Console.WriteLine("Database decrypted in {0} ms", stopWatch.ElapsedMilliseconds);
        database.PrintEncryptedDbInfo(Console.Out);
        return 0;
    }
    catch (Exception e)
    {
        Console.WriteLine("Database decrypt failed in {0} ms with error {1}", stopWatch.ElapsedMilliseconds, e.Message);
        return 1;
    }
}

SecureString ReadPassword()
{
    var password = new SecureString();
    while (true)
    {
        ConsoleKeyInfo key = Console.ReadKey(true);
        switch (key.Key)
        {
            case ConsoleKey.Enter:
                Console.WriteLine();
                return password;
            case ConsoleKey.Backspace:
                if (password.Length > 0)
                    password.RemoveAt(password.Length - 1);
                break;
            default:
                if (key.KeyChar >= ' ')
                    password.AppendChar(key.KeyChar);
                break;
        }
    }
}