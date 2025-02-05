package info.malenkov.aspiahwinfo;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.net.util.SubnetUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.gson.Gson;
import com.google.protobuf.ByteString;

import info.malenkov.aspiahwinfo.proto.ClientHello;
import info.malenkov.aspiahwinfo.proto.Encryption;
import info.malenkov.aspiahwinfo.proto.EventLogs;
import info.malenkov.aspiahwinfo.proto.EventLogsData;
import info.malenkov.aspiahwinfo.proto.Identify;
import info.malenkov.aspiahwinfo.proto.ServerHello;
import info.malenkov.aspiahwinfo.proto.SessionChallenge;
import info.malenkov.aspiahwinfo.proto.SessionResponse;
import info.malenkov.aspiahwinfo.proto.SessionType;
import info.malenkov.aspiahwinfo.proto.SrpClientKeyExchange;
import info.malenkov.aspiahwinfo.proto.SrpIdentify;
import info.malenkov.aspiahwinfo.proto.SrpServerKeyExchange;
import info.malenkov.aspiahwinfo.proto.SystemInfo;
import info.malenkov.aspiahwinfo.proto.SystemInfoRequest;
import info.malenkov.aspiahwinfo.proto.Version;

public class Engine {
    private final int THREADS_POOL_SIZE = 20;
    //private final String SPLIT = "<-//->";
	private List<HostInfo> foundHosts = new ArrayList<>();
    private final String HOST_OS = System.getProperty("os.name") + " (" + System.getProperty("os.arch") + "), " + System.getProperty("java.vm.specification.vendor") + " Java " + System.getProperty("java.vm.specification.version") + " (Version: " + System.getProperty("java.vm.version") + ") " ;
    private final Gson gson = new Gson();

    Engine(){
		System.out.println();
		System.out.println(Shared.APP_NAME + " v." + Shared.APP_MAJOR_VERSION + "." + Shared.APP_MINOR_VERSION);
		System.out.println();
        Security.addProvider(new BouncyCastleProvider());
    }

    public void run(){
		try {
            netScan();
        } catch (InterruptedException | ExecutionException | IOException e) {
            e.printStackTrace();
        }
    }

	private void netScan() throws InterruptedException, ExecutionException, IOException{
		if(Shared.network != null) {
            if(Shared.network.indexOf(":") > 0){
                String buffer[] = Shared.network.split(":");
                Shared.network = buffer[0]; 
                Shared.aspiaPort = Integer.valueOf(buffer[1]); 
            }

            final SubnetUtils utils = new SubnetUtils(Shared.network);
            String[] allIps = utils.getInfo().getAllAddresses();
            final ExecutorService es = Executors.newFixedThreadPool(THREADS_POOL_SIZE);
            final List<Future<Boolean>> futures = new ArrayList<>();
    
			if(Shared.network.indexOf("/32") > 0){
				allIps = new String[1];
				allIps[0] = Shared.network.substring(0, Shared.network.indexOf("/32"));
			}

            for (String ip : allIps) {
              futures.add(portIsOpen(es, ip, Shared.aspiaPort, Shared.ipTimeout));
            }
            
            es.shutdown();
            int openPorts = 0;
            for (final Future<Boolean> f : futures) {
                if (f.get()) {
                  openPorts++;
                }
            }
        
            System.out.println("\nThere are " + openPorts + " open ports on network " + Shared.network + " (probed with a timeout of " + Shared.ipTimeout + "ms)");
        
            if(openPorts > 0){
				if(foundHosts.size() > 0){
					try (BufferedWriter bufferedWriter = Files.newBufferedWriter(Paths.get(Shared.jsonExportFile), StandardCharsets.UTF_8)) {
						int count = 0;
						int size = foundHosts.size();
						bufferedWriter.write("{");
						for (HostInfo foundHost: foundHosts) {
							String report = "\""+ foundHost.hostIp + "\":" + foundHost.hostHWInfo;
							bufferedWriter.write(report);
							if(++count < size){
								bufferedWriter.write(",");
							}
						}
						bufferedWriter.write("}");
						bufferedWriter.close();
					}
				}
			}
        }
    }

    private Future<Boolean> portIsOpen(final ExecutorService es, final String ip, final int port, final int timeout) {
        return es.submit(new Callable<Boolean>() {
            @Override public Boolean call() {
              try {
				int TEST_TIMEOUT = 600;
				String hostIp = null;
				String hostNameByIP = null;
                String hostNameByAspia = null;
				HWDataWrapper hwData = new HWDataWrapper();
				AtomicReference<HWDataWrapper> refHWData = new AtomicReference<>(hwData);

				Socket socket = new Socket();
                socket.connect(new InetSocketAddress(ip, port), TEST_TIMEOUT);
                socket.close();

                hostIp = ip;
                hostNameByIP = getHostName(ip);
				hostNameByAspia = getHostInfo(ip, Shared.hostUser, Shared.hostPassword, refHWData);
                foundHosts.add(new HostInfo(hostIp, hostNameByIP, hostNameByAspia, refHWData.get().hwInfoJSON));

                System.out.print("+");
                return true;
              } catch (Exception ex) {
                System.out.print(".");
                return false;
              }
            }
        });
    }

	private String getHostName(String ip){
		String result = ip;

		InetAddress addr;
		try {
			addr = InetAddress.getByName(ip);
			result = addr.getHostName();
		} catch (UnknownHostException e) {
			// Do nothing
			System.out.println("\n<!> getHostName(" + ip + ") error: " + e);
		}

		return result;
	}

	private String getHostInfo(String hostIp, String hostUser, String hostPassword, AtomicReference<HWDataWrapper> refHWData){
		String result = "<!> Wrong user name or password";
		Encryption serverEncryption = Encryption.ENCRYPTION_UNKNOWN;
		SPREngine sprEngine = null;
		boolean alwaysFine = true;
		byte[] data = null;
		ArrayList<String> hwJSONRecords = new ArrayList<>();
		refHWData.get().hwInfoJSON = "";

		try{
			Socket socket = new Socket(hostIp, Shared.aspiaPort);
			socket.setSoTimeout(Shared.ipTimeout);
			BufferedOutputStream out = new BufferedOutputStream(socket.getOutputStream());
			BufferedInputStream in = new BufferedInputStream(socket.getInputStream());

			// ---->>> ClientHello
			ClientHello clientHello = ClientHello.newBuilder()
					.setEncryption(Encryption.ENCRYPTION_CHACHA20_POLY1305_VALUE | Encryption.ENCRYPTION_AES256_GCM_VALUE)
					.setIdentify(Identify.IDENTIFY_SRP)
					.build();
			byte[] clientHelloDATA = Protobuf.addSize(clientHello.toByteArray());
			out.write(clientHelloDATA);
			out.flush();

			// <<<---- ServerHello
			if(alwaysFine){
				data = Protobuf.read(in);
				if (data.length > 0) {
					data = Protobuf.skipSize(data);
					if (Protobuf.var128Decode(data) > 0) {
						ServerHello serverHello = ServerHello.parseFrom(data);
						serverEncryption = serverHello.getEncryption();
					}else{
						System.out.print("<!> ServerHello protobuf error.");
						alwaysFine = false;
					}
				}else{
					System.out.print("<!> ServerHello error.");
					alwaysFine = false;
				}
			}

			// ---->>> SrpIdentify
			if(alwaysFine){
				SrpIdentify srpIdentify = SrpIdentify.newBuilder().setUsername(hostUser).build();
				byte[] srpIdentifyDATA = Protobuf.addSize(srpIdentify.toByteArray());
				out.write(srpIdentifyDATA);
				out.flush();
			}
			
			// <<<---- SrpServerKeyExchange
			if(alwaysFine){
				data = Protobuf.read(in);
				if (data.length > 0) {
					if (Protobuf.var128Decode(data) > 0) {
						data = Protobuf.skipSize(data);
						SrpServerKeyExchange srpServerKeyExchange = SrpServerKeyExchange.parseFrom(data);
						sprEngine = new SPREngine(hostUser , hostPassword, 
							serverEncryption,
							srpServerKeyExchange.getNumber().toByteArray(), 
							srpServerKeyExchange.getGenerator().toByteArray(), 
							srpServerKeyExchange.getSalt().toByteArray(), 
							srpServerKeyExchange.getB().toByteArray(), 
							srpServerKeyExchange.getIv().toByteArray());
					}else{
						System.out.print("<!> SprServerKeyExchange protobuf error.");
						alwaysFine = false;
					}
				}else{
					System.out.print("<!> SprServerKeyExchange error.");
					alwaysFine = false;
				}
			}

			// ---->>> SrpClientKeyExchange
			if(alwaysFine && sprEngine != null){
				SrpClientKeyExchange srpClientKeyExchange = SrpClientKeyExchange.newBuilder()
					.setA(ByteString.copyFrom(sprEngine.getA()))
					.setIv(ByteString.copyFrom(sprEngine.getIV()))
					.build();

				byte[] srpClientKeyExchangeDATA = Protobuf.addSize(srpClientKeyExchange.toByteArray());
				out.write(srpClientKeyExchangeDATA);
				out.flush();
			}
			// <<<----- SessionChallenge
			if(alwaysFine && sprEngine != null){
				data = Protobuf.read(in);
				if (data.length > 0) {
					if (Protobuf.var128Decode(data) > 0) {
						data = Protobuf.skipSize(data);
						SessionChallenge sessionChallenge = SessionChallenge.parseFrom(sprEngine.decrypt(data));
						result = sessionChallenge.getComputerName(); 
					}else{
						//result = "<!> SessionChallenge protobuf error.";
						result = result + "\nSessionChallenge protobuf error."; 
						alwaysFine = false;
					}
				}else{
					// result = "<!> SessionChallenge error.";
					result = result + "\nSessionChallenge error."; 
					alwaysFine = false;
				}
			}

			// ---->>> SessionResponse
			if(alwaysFine && sprEngine != null){
				Version aspiaBookVersion = Version.newBuilder()
					.setMajor(Shared.ASPIA_MAJOR)
					.setMinor(Shared.ASPIA_MINOR)
					.setPatch(Shared.ASPIA_PATCH)
					.setRevision(Shared.ASPIA_REVISION)
					.build();
				SessionResponse sessionResponse = SessionResponse.newBuilder()
					.setSessionType(SessionType.SESSION_TYPE_SYSTEM_INFO_VALUE)
					.setVersion(aspiaBookVersion)
					.setCpuCores(1)
					.setOsName(HOST_OS)
					.setComputerName(Shared.APP_NAME + " v." + Shared.APP_MAJOR_VERSION + "." + Shared.APP_MINOR_VERSION + "." + Shared.APP_PATCH + " Rev.:" + Shared.APP_REVISION)
					.build();
				byte[] sessionResponseDATA = Protobuf.addSize(sprEngine.encrypt(sessionResponse.toByteArray()));
				out.write(sessionResponseDATA);
				out.flush();
			}

			final String SystemInfo_Summary = "D9FE7CED-175C-4069-AB80-9B4F897EB376";
			final String SystemInfo_Devices = "1451B77D-276E-47BB-989B-D8B61A468F8B";
			final String SystemInfo_VideoAdapters = "D2867BED-1408-467C-8ABE-6BD8B32DE17B";
			final String SystemInfo_Monitors = "344E1796-EFF2-4F4D-B48B-3A10CEA834B8";
			final String SystemInfo_Printers = "19193E9A-D2A6-44F8-83D2-A6B0F8651DAC";
			final String SystemInfo_PowerOptions = "838C76EA-D13F-4718-8C7E-D483221ECF99";
			final String SystemInfo_Drivers = "82E18359-39CC-41FA-A8DA-70077F1340FB";
			final String SystemInfo_Services = "F56D910E-9A08-4459-8F11-F0F42817F0CD";
			final String SystemInfo_EnvironmentVariables = "F06EA182-23FB-4347-9C9E-F66582C9EF71";
			final String SystemInfo_EventLogs = "8F2499F5-30B8-42B5-82DF-6FBE0BCCDD6F";
			final String SystemInfo_NetworkAdapters = "A27B3B0E-BF55-43B3-989B-40705DAF3290";
			final String SystemInfo_Routes = "224C9198-FF86-40B6-96FD-19938B952021";
			final String SystemInfo_Connections = "E720729A-7C96-4603-A46B-91FBC95420D6";
			final String SystemInfo_NetworkShares = "EC295A1A-6CBD-4334-9697-38E542687902";
			final String SystemInfo_Licenses = "7D3320B3-E5A6-43AD-8768-09F9304CEFC7";
			final String SystemInfo_Applications = "E2057608-971B-439C-9A2E-31CB0BA6C6CC";
			final String SystemInfo_OpenFiles = "F851332D-D70E-4D68-A30D-7A3F00E69324";

			///////////////////////////////////////////////////////////////////////////////////////
			//
			// Summary
			//

			// ----->>> SystemInfo_Summary
			if(alwaysFine && sprEngine != null){
				SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
					.setCategory(SystemInfo_Summary)
					.build();
				byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
				out.write(systemInfoRequestDATA);
				out.flush();
			}

			// <<<----- SystemInfo_Summary
			if(alwaysFine && sprEngine != null){
				data = Protobuf.read(in);
				if (data.length > 0) {
					if (Protobuf.var128Decode(data) > 0) {
						data = Protobuf.skipSize(data);
						SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
						String tmpJSONRecord = "\"Summary\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
						if(tmpJSONRecord != null && tmpJSONRecord.length() > 0) hwJSONRecords.add(tmpJSONRecord);
					}else{
						result = result + "\nSessionChallenge protobuf error."; 
						alwaysFine = false;
					}
				}else{
					result = result + "\nSessionChallenge error."; 
					alwaysFine = false;
				}
			}

			if(Shared.fullReport){

				///////////////////////////////////////////////////////////////////////////////////////
				// 
				// Devices
				//

				// ----->>> SystemInfo_Devices
				if(alwaysFine && sprEngine != null){
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_Devices)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_Devices
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							String tmpJSONRecord = "\"Devices\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
							if(tmpJSONRecord != null && tmpJSONRecord.length() > 0) hwJSONRecords.add(tmpJSONRecord);
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}

				///////////////////////////////////////////////////////////////////////////////////////
				//
				// VideoAdapters
				//

				// ----->>> SystemInfo_Summary
				if(alwaysFine && sprEngine != null){
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_VideoAdapters)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_VideoAdapters
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							String tmpJSONRecord = "\"VideoAdapters\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
							if(tmpJSONRecord != null && tmpJSONRecord.length() > 0) hwJSONRecords.add(tmpJSONRecord);
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}

				///////////////////////////////////////////////////////////////////////////////////////
				//
				// Monitors
				//

				// ----->>> SystemInfo_Monitors
				if(alwaysFine && sprEngine != null){
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_Monitors)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_Monitors
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							String tmpJSONRecord = "\"Monitors\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
							if(tmpJSONRecord != null && tmpJSONRecord.length() > 0) hwJSONRecords.add(tmpJSONRecord);
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}

				///////////////////////////////////////////////////////////////////////////////////////
				//
				// Printers
				//

				// ----->>> SystemInfo_Printers
				if(alwaysFine && sprEngine != null){
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_Printers)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_Printers
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							String tmpJSONRecord = "\"Printers\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
							if(tmpJSONRecord != null && tmpJSONRecord.length() > 0) hwJSONRecords.add(tmpJSONRecord);
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}

				///////////////////////////////////////////////////////////////////////////////////////
				//
				// PowerOptions
				//

				// ----->>> SystemInfo_PowerOptions
				if(alwaysFine && sprEngine != null){
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_PowerOptions)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_PowerOptions
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							String tmpJSONRecord = "\"PowerOptions\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
							if(tmpJSONRecord != null && tmpJSONRecord.length() > 0) hwJSONRecords.add(tmpJSONRecord);
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}

				///////////////////////////////////////////////////////////////////////////////////////
				//
				// Drivers
				//

				// ----->>> SystemInfo_Drivers
				if(alwaysFine && sprEngine != null){
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_Drivers)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_Drivers
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							String tmpJSONRecord = "\"Drivers\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
							if(tmpJSONRecord != null && tmpJSONRecord.length() > 0) hwJSONRecords.add(tmpJSONRecord);
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}

				///////////////////////////////////////////////////////////////////////////////////////
				//
				// Services
				//

				// ----->>> SystemInfo_Services
				if(alwaysFine && sprEngine != null){
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_Services)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_Services
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							String tmpJSONRecord = "\"Services\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
							if(tmpJSONRecord != null && tmpJSONRecord.length() > 0) hwJSONRecords.add(tmpJSONRecord);
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}
				
				///////////////////////////////////////////////////////////////////////////////////////
				//
				// EnvironmentVariables
				//

				// ----->>> SystemInfo_EnvironmentVariables
				if(alwaysFine && sprEngine != null){
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_EnvironmentVariables)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_EnvironmentVariables
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							String tmpJSONRecord = "\"EnvironmentVariables\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
							if(tmpJSONRecord != null && tmpJSONRecord.length() > 0) hwJSONRecords.add(tmpJSONRecord);
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}

				///////////////////////////////////////////////////////////////////////////////////////
				//
				// EventLogs
				//

				String tmpJSONRecordEvents = "\"EventLogs\":{";

				// ----->>> SystemInfo_EventLogs (system)
				if(alwaysFine && sprEngine != null){
					EventLogsData eventLogsData = EventLogsData.newBuilder()
					.setType(EventLogs.Event.Type.TYPE_SYSTEM)
					.setRecordCount(Shared.eventLogMaxSize)
					.build();
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_EventLogs)
						.setEventLogsData(eventLogsData)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_EventLogs (system)
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							tmpJSONRecordEvents += "\"System\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "") + ",";
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}

				// ----->>> SystemInfo_EventLogs (application)
				if(alwaysFine && sprEngine != null){
					EventLogsData eventLogsData = EventLogsData.newBuilder()
					.setType(EventLogs.Event.Type.TYPE_APPLICATION)
					.setRecordCount(Shared.eventLogMaxSize)
					.build();
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_EventLogs)
						.setEventLogsData(eventLogsData)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_EventLogs (application)
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							tmpJSONRecordEvents += "\"Application\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "") + "," ;
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}

				// ----->>> SystemInfo_EventLogs (security)
				if(alwaysFine && sprEngine != null){
					EventLogsData eventLogsData = EventLogsData.newBuilder()
					.setType(EventLogs.Event.Type.TYPE_SECURITY)
					.setRecordCount(Shared.eventLogMaxSize)
					.build();
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_EventLogs)
						.setEventLogsData(eventLogsData)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_EventLogs (security)
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							tmpJSONRecordEvents += "\"Security\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}

				if(tmpJSONRecordEvents != null && tmpJSONRecordEvents.length() > 0) hwJSONRecords.add(tmpJSONRecordEvents + "}");

				///////////////////////////////////////////////////////////////////////////////////////
				// 
				// NetworkAdapters
				//

				// ----->>> SystemInfo_NetworkAdapters
				if(alwaysFine && sprEngine != null){
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_NetworkAdapters)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_NetworkAdapters
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							String tmpJSONRecord = "\"NetworkAdapters\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
							if(tmpJSONRecord != null && tmpJSONRecord.length() > 0) hwJSONRecords.add(tmpJSONRecord);
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}

				///////////////////////////////////////////////////////////////////////////////////////
				// 
				// Routes
				//

				// ----->>> SystemInfo_Routes
				if(alwaysFine && sprEngine != null){
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_Routes)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_Routes
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							String tmpJSONRecord = "\"Routes\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
							if(tmpJSONRecord != null && tmpJSONRecord.length() > 0) hwJSONRecords.add(tmpJSONRecord);
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}

				///////////////////////////////////////////////////////////////////////////////////////
				// 
				// Connections
				//

				// ----->>> SystemInfo_Connections
				if(alwaysFine && sprEngine != null){
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_Connections)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_Connections
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							String tmpJSONRecord = "\"Connections\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
							if(tmpJSONRecord != null && tmpJSONRecord.length() > 0) hwJSONRecords.add(tmpJSONRecord);
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}

				///////////////////////////////////////////////////////////////////////////////////////
				// 
				// NetworkShares
				//

				// ----->>> SystemInfo_NetworkShares
				if(alwaysFine && sprEngine != null){
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_NetworkShares)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_NetworkShares
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							String tmpJSONRecord = "\"NetworkShares\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
							if(tmpJSONRecord != null && tmpJSONRecord.length() > 0) hwJSONRecords.add(tmpJSONRecord);
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}

				///////////////////////////////////////////////////////////////////////////////////////
				// 
				// Licenses
				//

				// ----->>> SystemInfo_Licenses
				if(alwaysFine && sprEngine != null){
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_Licenses)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_Licenses
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							String tmpJSONRecord = "\"Licenses\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
							if(tmpJSONRecord != null && tmpJSONRecord.length() > 0) hwJSONRecords.add(tmpJSONRecord);
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}

				///////////////////////////////////////////////////////////////////////////////////////
				// 
				// Applications
				//

				// ----->>> SystemInfo_Applications
				if(alwaysFine && sprEngine != null){
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_Applications)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_Applications
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							String tmpJSONRecord = "\"Applications\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
							if(tmpJSONRecord != null && tmpJSONRecord.length() > 0) hwJSONRecords.add(tmpJSONRecord);
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}

				if(hwJSONRecords.size() > 0){
					int size = hwJSONRecords.size();
					int count = 0;
					String buffer = "{";

					for (String hwRecord : hwJSONRecords) {
						buffer += hwRecord;
						if(++count < size){
							buffer += ",";
						}
					}
					buffer += "}";
					refHWData.get().hwInfoJSON = buffer;
				}else{
					refHWData.get().hwInfoJSON = "no data";
				}

				///////////////////////////////////////////////////////////////////////////////////////
				// 
				// OpenFiles
				//

				// ----->>> SystemInfo_OpenFiles
				if(alwaysFine && sprEngine != null){
					SystemInfoRequest systemInfoRequest = SystemInfoRequest.newBuilder()
						.setCategory(SystemInfo_OpenFiles)
						.build();
					byte[] systemInfoRequestDATA = Protobuf.addSize(sprEngine.encrypt(systemInfoRequest.toByteArray()));
					out.write(systemInfoRequestDATA);
					out.flush();
				}

				// <<<----- SystemInfo_OpenFiles
				if(alwaysFine && sprEngine != null){
					data = Protobuf.read(in);
					if (data.length > 0) {
						if (Protobuf.var128Decode(data) > 0) {
							data = Protobuf.skipSize(data);
							SystemInfo systemInfo = SystemInfo.parseFrom(sprEngine.decrypt(data));
							String tmpJSONRecord = "\"OpenFiles\":" + gson.toJson(systemInfo.getAllFields()).replace(Shared.appPackage + ".proto.", "");
							if(tmpJSONRecord != null && tmpJSONRecord.length() > 0) hwJSONRecords.add(tmpJSONRecord);
						}else{
							result = result + "\nSessionChallenge protobuf error."; 
							alwaysFine = false;
						}
					}else{
						result = result + "\nSessionChallenge error."; 
						alwaysFine = false;
					}
				}
			}

			if(hwJSONRecords.size() > 0){
				int size = hwJSONRecords.size();
				int count = 0;
				String buffer = "{";

				for (String hwRecord : hwJSONRecords) {
					buffer += hwRecord;
					if(++count < size){
						buffer += ",";
					}
				}
				buffer += "}";
				refHWData.get().hwInfoJSON = buffer;
			}else{
				refHWData.get().hwInfoJSON = "no data";
			}

            socket.close();
		} catch (Exception e) {
			result = result + "\n" + e; 
			refHWData.get().hwInfoJSON = "\"" + e.getMessage() + "\"";
		}

		return result;
	}


	class HWDataWrapper{
		String hwInfoJSON;
	}

    class HostInfo{
        String hostIp;
        String hostNameByIP;
        String hostNameByAspia;
		String hostHWInfo;

        public HostInfo(String ip, String nameByIP, String nameByAspia, String hwInfo){
            hostIp = ip;
            hostNameByIP = nameByIP;
            hostNameByAspia = nameByAspia;
			hostHWInfo = hwInfo;
        }

        public String getIp(){
            return hostIp;
        }

        public String getName(){
            return hostNameByIP;
        }

        public String getAspiaName(){
            return hostNameByAspia;
        }

		public String getHWInfo(){
			return hostHWInfo;
		}
    }
}
