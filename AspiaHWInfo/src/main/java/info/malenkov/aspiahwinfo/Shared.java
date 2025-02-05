package info.malenkov.aspiahwinfo;

public class Shared {
	public static final int MIN_JAVA_VERSION = 8;
	public final static String APP_NAME = "AspiaHWInfo";
	public final static String APP_COPYRIGHT = "(c) Copyright 2025 Maxim V. Malenkov\n\nThird-party component:\n- guava (c) 2009 Google Inc.; Apache-2.0 license\n- protobuf (c) 2008 Google Inc.; BSD 3-Clause License\n- bouncycastle (c) 2000 - 2021 The Legion of the Bouncy Castle Inc; MIT license";
	public final static String APP_WEB = "https://github.com/diwizard/aspiahwinfo";
	public final static int APP_MAJOR_VERSION = 1;
	public final static int APP_MINOR_VERSION = 0;
	public final static int APP_PATCH = 0;
	public final static int APP_REVISION = 0;

    public final static int ASPIA_MAJOR = 2;
	public final static int ASPIA_MINOR = 4;
	public final static int ASPIA_PATCH = 0;
	public final static int ASPIA_REVISION = 4038;

	public static String appPackage = "";
    public final static int THREADS_POOL_SIZE = 20;
	public static int aspiaPort = 8050;
    public static int ipTimeout = 600;
	public static String network = "";
    public static String hostUser = "";
	public static String hostPassword = "";
    public static String jsonExportFile = "";
	public static int eventLogMaxSize = 100;
	public static boolean fullReport = false;
}
