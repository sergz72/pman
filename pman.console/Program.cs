using System.Diagnostics;
using pman.keepass;

switch (args.Length)
{
    case 1:
        Console.WriteLine("Opening database file {0}...", args[0]);
        Console.Write("Password: ");
        var password = ReadPassword();
        return Start(password);
    case 2:
        Console.WriteLine("Opening database file {0}...", args[0]);
        return Start(args[1]);
    default:
        Console.WriteLine("Usage: pman db_name [password]");
        return 1;
}

int Start(string password)
{
    Stopwatch stopWatch = new Stopwatch();
    stopWatch.Start();
    try
    {
        var database = new KeePassDb(args[0], password, null);
        Console.WriteLine("Database opened in {0}", stopWatch.Elapsed);
        database.PrintDbInfo(Console.Out);
        return 0;
    }
    catch (Exception e)
    {
        Console.WriteLine("Database failed in {0} with error {1}", stopWatch.Elapsed, e.Message);
        return 1;
    }
}

string ReadPassword()
{
    string password = "";
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
                    password = password.Substring(0, (password.Length - 1));
                break;
            default:
                password += key.KeyChar;
                break;
        }
    }
}