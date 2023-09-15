﻿using UIKit;

namespace pman.maui;

public class Program
{
    // This is the main entry point of the application.
    static void Main(string[] args)
    {
        #if DEBUG
        Thread.Sleep(4000);
        #endif
        // if you want to use a different Application Delegate class from "AppDelegate"
        // you can specify it here.
        UIApplication.Main(args, null, typeof(AppDelegate));
    }
}