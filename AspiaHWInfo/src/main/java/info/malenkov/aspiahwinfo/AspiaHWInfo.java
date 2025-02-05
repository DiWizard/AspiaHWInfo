package info.malenkov.aspiahwinfo;

import java.net.InetAddress;

public class AspiaHWInfo {
	private static final String CLK_IPNET = "--network";
	private static final String CLK_IPNET_S = "-n";

	private static final String CLK_HOSTUSER = "--hostUser";
	private static final String CLK_HOSTUSER_S = "-u";
	
	private static final String CLK_HOSTPSW = "--hostPassword";
	private static final String CLK_HOSTPSW_S = "-p";

	private static final String CLK_EXPORT = "--export";
	private static final String CLK_EXPORT_S = "-x";

	private static final String CLK_HELP = "--help";
	private static final String CLK_HELP_S = "-h";

	private static final String CLK_LIMIT = "--limit";
	private static final String CLK_LIMIT_S = "-l";

	private static final String CLK_FULL = "--all";
	private static final String CLK_FULL_S = "-a";

	private static final String CLK_TIMEOUT = "--timeout";
	private static final String CLK_TIMEOUT_S = "-t";

	private static final String CLK_VER = "--version";
	private static final String CLK_VER_S = "-v";

	private static final String CLK_JAVA = "--java";
	private static final String CLK_JAVA_S = "-j";

	private static String commandLineKeys[] = {
		CLK_EXPORT, CLK_EXPORT_S,
		CLK_IPNET, CLK_IPNET_S,
		CLK_HELP, CLK_HELP_S,
		CLK_LIMIT, CLK_LIMIT_S,
		CLK_FULL, CLK_FULL_S,
		CLK_VER, CLK_VER_S,
		CLK_JAVA, CLK_JAVA_S,
		CLK_TIMEOUT, CLK_TIMEOUT_S,
		CLK_HOSTUSER, CLK_HOSTUSER_S,
		CLK_HOSTPSW, CLK_HOSTPSW_S
	};

	private static CommandLineParcer commandLineParcer;

    public static void main(String[] args) {
		Shared.appPackage = new Object(){}.getClass().getPackage().getName().toLowerCase();

		commandLineParcer = new CommandLineParcer(args, commandLineKeys);
		testJava();
		loadSettings();

		Engine engine = new Engine();
		engine.run();
    }

	private static void help(){
		System.out.println("Usage: AspiaHWInfo -nupx[tvjh]");
		System.out.println();
		System.out.println("Required arguments: ");
		System.out.println("  -n=<..>, --network=<..>            TCP/IP network [:port] for scan");
		System.out.println("  -u=<..>, --hostUser=<..>           Aspia host user name");
		System.out.println("  -p=<..>, --hostPassword=<..>       Aspia host user password");
		System.out.println("  -x=<..>, --export=<..>             Export scan results to JSON-file");
		System.out.println();
		System.out.println("Optional arguments: ");
		System.out.println("  -l=<..>, --limit=<..>              Limitation on exporting event log entries to JSON-file");
		System.out.println("  -a=<..>, --all=<..>                Export all data to JSON-file");
		System.out.println("  -t=<..>, --timeout=<..>            Timeout in milliseconds (min: 200, max 5000)");
		System.out.println("  -v,      --version                 print AspiaHWInfo version");		
		System.out.println("  -j,      --java                    print Java version");		
		System.out.println("  -h,      --help                    this help");		
		System.out.println();
		System.out.println("Usage example: ");
		System.out.println("  AspiaHWInfo -n=192.168.1.0/24:8050 -u=AspiaUser -p=Pa$$word -x=\"d:\\hwinfo.json\"");
		System.out.println();
	}

	public static void printFullJVMInfo(){
		System.out.println("");
		// java.version						Java Runtime Environment version, which may be interpreted as a Runtime.Version
		System.out.println("Java Runtime Environment version: " + System.getProperty("java.version"));
		// java.version.date				Java Runtime Environment version date, in ISO-8601 YYYY-MM-DD format, which may be interpreted as a java.time.LocalDate
		System.out.println("Java Runtime Environment version date: " + System.getProperty("java.version.date"));
		// java.vendor						Java Runtime Environment vendor
		System.out.println("Java Runtime Environment vendor: " + System.getProperty("java.vendor"));
		// java.vendor.url					Java vendor URL
		System.out.println("Java vendor URL: " + System.getProperty("java.vendor.url"));
		// java.vendor.version				Java vendor version
		System.out.println("Java vendor version: " + System.getProperty("java.vendor.version"));
		// java.home						Java installation directory
		System.out.println("Java installation directory: " + System.getProperty("java.home"));
		// java.vm.specification.version	Java Virtual Machine specification version, whose value is the feature element of the runtime version
		System.out.println("Java Virtual Machine specification version: " + System.getProperty("java.vm.specification.version"));
		// java.vm.specification.vendor		Java Virtual Machine specification vendor
		System.out.println("Java Virtual Machine specification vendor: " + System.getProperty("java.vm.specification.vendor"));
		// java.vm.specification.name		Java Virtual Machine specification name
		System.out.println("Java Virtual Machine specification name: " + System.getProperty("java.vm.specification.name"));
		// java.vm.version					Java Virtual Machine implementation version which may be interpreted as a Runtime.Version
		System.out.println("Java Virtual Machine implementation version: " + System.getProperty("java.vm.version"));
		// java.vm.vendor					Java Virtual Machine implementation vendor
		System.out.println("Java Virtual Machine implementation vendor: " + System.getProperty("java.vm.vendor"));
		// java.vm.name						Java Virtual Machine implementation name
		System.out.println("Java Virtual Machine implementation name: " + System.getProperty("java.vm.name"));
		// java.specification.version		Java Runtime Environment specification version, whose value is the feature element of the runtime version
		System.out.println("Java Runtime Environment specification version: " + System.getProperty("java.specification.version"));
		// java.specification.vendor		Java Runtime Environment specification vendor
		System.out.println("Java Runtime Environment specification vendor: " + System.getProperty("java.specification.vendor"));
		// java.specification.name			Java Runtime Environment specification name
		System.out.println("Java Runtime Environment specification name: " + System.getProperty("java.specification.name"));
		// java.class.version				Java class format version number
		System.out.println("Java class format version number: " + System.getProperty("java.class.version"));
		// java.class.path					Java class path (refer to ClassLoader.getSystemClassLoader() for details)
		System.out.println("Java class path: " + System.getProperty("java.class.path"));
		// java.library.path				List of paths to search when loading libraries
		System.out.println("List of paths to search when loading libraries: " + System.getProperty("java.library.path"));
		// java.io.tmpdir					Default temp file path
		System.out.println("Default temp file path: " + System.getProperty("java.io.tmpdir"));
		// java.compiler					Name of JIT compiler to use
		System.out.println("Name of JIT compiler to use: " + System.getProperty("java.compiler"));
		// Host name
		try{ System.out.println("Host name: " + InetAddress.getLocalHost().getHostName()); }
		catch(Exception e){ System.out.println("Host name: <Unknown>"); }
		// os.name							Operating system name
		System.out.println("Operating system name: " + System.getProperty("os.name"));
		// os.arch							Operating system architecture
		System.out.println("Operating system architecture: " + System.getProperty("os.arch"));
		// os.version						Operating system version
		System.out.println("Operating system version: " + System.getProperty("os.version"));
		// file.separator					File separator ("/" on UNIX)
		System.out.println("File separator: " + System.getProperty("file.separator"));
		// path.separator					Path separator (":" on UNIX)
		System.out.println("Path separator: " + System.getProperty("path.separator"));
		// line.separator					Line separator ("\n" on UNIX)
		System.out.println("Line separator: " + System.getProperty("line.separator"));
		// user.name						User's account name
		System.out.println("User's account name: " + System.getProperty("user.name"));
		// user.home						User's home directory
		System.out.println("User's home directory: " + System.getProperty("user.home"));
		// user.dir							User's current working directory
		System.out.println("User's current working directory: " + System.getProperty("user.dir"));
		System.out.println("");
	}

	private static void wrongJava(){
		System.out.println("<!>: Requires Java VM version " + Shared.MIN_JAVA_VERSION + " or higher!");
		System.out.println("Please, download your version from: ");
		System.out.println("1. Oracle - https://www.java.com/");
		System.out.println("2. Azul - https://www.azul.com/");
		System.out.println("3. Gluon - https://gluonhq.com/");
		System.out.println("... or install any other JRE/JDK " + Shared.MIN_JAVA_VERSION + "+ build you are prefer.");
		System.exit(0);
	}

	private static void testJava(){
		String jv = System.getProperty("java.version");
		if(jv != null){
			if(jv.length() > 0){
				String[] jva = jv.split("\\.");

				if(jva.length < 2){
					System.out.println("<!> Unknown Java version: " + jv);
					System.exit(0);
				}

				if(jva[0].equals("1")){
					if(Integer.parseInt(jva[1]) < Shared.MIN_JAVA_VERSION){
						wrongJava();
					}
				}else{
					if(Integer.parseInt(jva[0]) < Shared.MIN_JAVA_VERSION){
						wrongJava();
					}
				}
			}
		}else{
			wrongJava();
		}
	}

    public static void printVersion(){
		System.out.println(Shared.APP_NAME + " v." + Shared.APP_MAJOR_VERSION + "." + Shared.APP_MINOR_VERSION);
		System.out.println(Shared.APP_WEB);
		System.out.println("");
		System.out.println(Shared.APP_COPYRIGHT);
		System.out.println("");
		if(System.getProperty("java.vendor").length() > 0 && System.getProperty("java.version").length() > 0){
			System.out.println("JavaVM version: " + System.getProperty("java.vendor") + " " + System.getProperty("java.version"));
			if(System.getProperty("os.name").length() > 0 && System.getProperty("os.arch").length() > 0){
				System.out.println("Running on " + System.getProperty("os.name") + " (" + System.getProperty("os.arch") + ")");
			}
		}
        System.out.println("");
	}

	public static void loadSettings(){
		if(commandLineParcer.getKeysCount() == 0 || commandLineParcer.getUnknownKeysCount() > 0){
			help();
			System.exit(0);
		}else if(commandLineParcer.isKeyExist(CLK_HELP_S) || commandLineParcer.isKeyExist(CLK_HELP)){
			help();
			System.exit(0);
		}else if(commandLineParcer.isKeyExist(CLK_JAVA_S) || commandLineParcer.isKeyExist(CLK_JAVA)){
			printFullJVMInfo();
			System.exit(0);
		}else if(commandLineParcer.isKeyExist(CLK_VER_S) || commandLineParcer.isKeyExist(CLK_VER)){
			printVersion();
			System.exit(0);
		}else{
			// Network 
			if(commandLineParcer.isKeyExist(CLK_IPNET_S)) Shared.network = commandLineParcer.getKeyValue(CLK_IPNET_S);
			if(commandLineParcer.isKeyExist(CLK_IPNET)) Shared.network = commandLineParcer.getKeyValue(CLK_IPNET);
			if(!commandLineParcer.isKeyExist(CLK_IPNET_S) && !commandLineParcer.isKeyExist(CLK_IPNET)){
				System.out.println("<!> Error: "+ CLK_IPNET + " key is required.\n");
				help();
				System.exit(0);
			}
			// Network timeout
			if(commandLineParcer.isKeyExist(CLK_TIMEOUT_S)) Shared.ipTimeout = Integer.parseInt(commandLineParcer.getKeyValue(CLK_TIMEOUT_S));
			if(commandLineParcer.isKeyExist(CLK_TIMEOUT)) Shared.ipTimeout = Integer.parseInt(commandLineParcer.getKeyValue(CLK_TIMEOUT));
			// Aspia host user
			if(commandLineParcer.isKeyExist(CLK_HOSTUSER_S)) Shared.hostUser = commandLineParcer.getKeyValue(CLK_HOSTUSER_S);
			if(commandLineParcer.isKeyExist(CLK_HOSTUSER))  Shared.hostUser = commandLineParcer.getKeyValue(CLK_HOSTUSER);
			if(!commandLineParcer.isKeyExist(CLK_HOSTUSER_S) && !commandLineParcer.isKeyExist(CLK_HOSTUSER)){
				System.out.println("<!> Error: "+ CLK_HOSTUSER + " key is required.\n");
				help();
				System.exit(0);
			}
			// Aspia host pasword
			if(commandLineParcer.isKeyExist(CLK_HOSTPSW_S))	Shared.hostPassword = commandLineParcer.getKeyValue(CLK_HOSTPSW_S);
			if(commandLineParcer.isKeyExist(CLK_HOSTPSW)) Shared.hostPassword = commandLineParcer.getKeyValue(CLK_HOSTPSW);
			if(!commandLineParcer.isKeyExist(CLK_HOSTPSW_S) && !commandLineParcer.isKeyExist(CLK_HOSTPSW)){
				System.out.println("<!> Error: "+ CLK_HOSTPSW + " key is required.\n");
				help();
				System.exit(0);
			}
			// JSON file
			if(commandLineParcer.isKeyExist(CLK_EXPORT_S)) Shared.jsonExportFile = commandLineParcer.getKeyValue(CLK_EXPORT_S);
			if(commandLineParcer.isKeyExist(CLK_EXPORT)) Shared.jsonExportFile = commandLineParcer.getKeyValue(CLK_EXPORT);
			if(!commandLineParcer.isKeyExist(CLK_EXPORT_S) && !commandLineParcer.isKeyExist(CLK_EXPORT)){
				System.out.println("<!> Error: "+ CLK_EXPORT + " key is required.\n");
				help();
				System.exit(0);
			}
			// Limit
			if(commandLineParcer.isKeyExist(CLK_LIMIT_S)) Shared.eventLogMaxSize = Integer.parseInt(commandLineParcer.getKeyValue(CLK_LIMIT_S));
			if(commandLineParcer.isKeyExist(CLK_LIMIT)) Shared.eventLogMaxSize = Integer.parseInt(commandLineParcer.getKeyValue(CLK_LIMIT));
			// Full export
			if(commandLineParcer.isKeyExist(CLK_FULL_S)) Shared.fullReport = true;
			if(commandLineParcer.isKeyExist(CLK_FULL)) Shared.fullReport = true;
		}
	}
}
