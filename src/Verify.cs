using System;
using System.Collections.Generic;

using System.Threading.Tasks;
using DNS;
using DNS.Client;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

namespace MailVerifier
{
	public class Verify
	{
		// 2018-12-06 get mx record domains
		public static IList<string> GetMxDomains (
			string address
		) {
			if (string.IsNullOrEmpty (address)) {
				throw new ArgumentNullException ("an email address is required");
			}
			if (!address.Contains ("@")) {
				throw new ArgumentException ("this is clearly not an email address");
			}
			if (address.Length < 6) {
				throw new ArgumentException ("this is not an email address, try again");
			}

			address = address.ToLower ().Trim ();
			string domain = address.Split ('@')[1];

			if (dnsIps.Count == 0) {
				throw new ArgumentException ("Please supply DNS ip's to use for this check");
			}

			IList<string> mxs = new List<string> ();

			foreach (string dnsIp in dnsIps) {
				Console.ForegroundColor = ConsoleColor.DarkGray;
				Console.WriteLine ("attempting to resolve DNS for " + domain + "... with dns server " + dnsIp);
				Console.ResetColor ();

				Task<IResponse> resp = null;
				try {
					resp = GetAnswersAsync (domain, RecordType.MX, dnsServer: dnsIp);
				} catch (Exception oops) {
					Console.WriteLine ("(MX failure against dns '" + dnsIp + "' for '" + domain + "') ");
					Console.WriteLine (oops.ToString ());
					continue;
				}

				if (resp == null) {
					Console.WriteLine ("(MX name failure against dns '" + dnsIp + "' for '" + domain + "') ");
					continue;
				}

				resp.Wait ();

				if (resp == null || resp.Result == null) {
					Console.WriteLine ("(MX against dns '" + dnsIp + "' fail for '" + domain + "') ");
					continue;
				}

				if (resp.Result.ResponseCode == ResponseCode.NameError) {
					Console.WriteLine ("(name error for '" + domain + "' with dns '" + dnsIp + "') ");
					continue;
				}

				IList<IResourceRecord> records = resp.Result.AnswerRecords;

				if (records == null || records.Count == 0) {
					Console.WriteLine ("(no MX records found for '" + domain + "' with dns '" + dnsIp + "') ");
					continue;
				}

				foreach (MailExchangeResourceRecord record in records) {
					string mx = record.ExchangeDomainName.ToString ();
					if (string.IsNullOrEmpty (mx)) {
						continue;
					}
					mx = mx.ToLower ();
					if (!mxs.Contains (mx)) {
						mxs.Add (mx);
					}
				}
			}

			return mxs;
		}

		public async static Task<IResponse> GetAnswersAsync (
			string domain,
			RecordType recordType,
			string dnsServer = "1.1.1.1",
			bool configureAwait = false
		) {
			ClientRequest request = new ClientRequest (dnsServer);

			request.Questions.Add (new Question (Domain.FromString (domain), recordType));
			request.RecursionDesired = true;

			IResponse response = null;

			try {
				response = await request.Resolve ().ConfigureAwait (continueOnCapturedContext: configureAwait);
			} catch (DNS.Client.ResponseException oops) {
				if (!oops.Message.Contains ("NameError")) {
					throw;
				}

				if (response != null && response.ResponseCode == ResponseCode.NameError) {
					return response;
				}

				return null;
			}

			return response;
		}

		public static Response Check (
			string address,
			int timeout = 10000
		) {
			if (string.IsNullOrEmpty (address)) {
				throw new ArgumentNullException ("an email address is required");
			}
			if (!address.Contains ("@")) {
				throw new ArgumentException ("this is clearly not an email address");
			}
			if (address.Length < 6) {
				throw new ArgumentException ("this is not an email address, try again");
			}

			address = address.ToLower ().Trim ();
			string domain = address.Split ('@')[1];

			if (dnsIps.Count == 0) {
				throw new ArgumentException ("Please supply DNS ip's to use for this check");
			}

			Response resp = new Response ();
			resp.Address = address;
			resp.Domain = domain;
			resp.Success = false;
			resp.Message = "";

			if (bypassDomains.ContainsKey (domain)) {
				resp.Success = true;
				resp.Message = "Success";
				return resp;
			}

			if (smtpPorts.Count == 0) {
				smtpPorts.Add (25);
				smtpPorts.Add (587);
			}

			bool realResponse = false;

			Console.ForegroundColor = ConsoleColor.Green;
			Console.WriteLine ("USING NEW LIBRARY");
			Console.ResetColor ();

			foreach (string dnsIp in dnsIps) {

				Console.ForegroundColor = ConsoleColor.DarkGray;
				Console.WriteLine ("attempting to resolve DNS for " + domain + "... with dns server " + dnsIp);
				Console.ResetColor ();

				Task<IResponse> mxResponse = null;
				try {
					mxResponse = GetAnswersAsync (domain, RecordType.MX, dnsServer: dnsIp);
					mxResponse.Wait ();
				} catch (Exception oops) {
					Console.WriteLine ("(MX against dns '" + dnsIp + "' fail for '" + domain + "') ");
					Console.WriteLine (oops.ToString ());
					resp.Message = "Error determining MX at dns '" + dnsIp + "' for '" + domain + "'";
					continue;
				}

				if (mxResponse == null || mxResponse.Result == null) {
					Console.WriteLine ("(MX against dns '" + dnsIp + "' fail for '" + domain + "') ");
					resp.Message = "MX not found at dns '" + dnsIp + "' for '" + domain + "'";
					continue;
				}

				if (mxResponse.Result.ResponseCode == ResponseCode.NameError) {
					Console.WriteLine ("(name error for '" + domain + "' with dns '" + dnsIp + "') ");
					resp.Message = "name error for '" + domain + "'";
					continue;
				}

				IList<IResourceRecord> records = mxResponse.Result.AnswerRecords;

				if (records == null || records.Count == 0) {
					Console.WriteLine ("(no MX records found for '" + domain + "' with dns '" + dnsIp + "') ");
					resp.Message = "no MX records for '" + domain + "'";
					continue;
				}

				bool serverVerified = false;

				foreach (IResourceRecord mRecord in records) {

					if (!(mRecord is MailExchangeResourceRecord)) {
						resp.Message = mRecord.Name.ToString () + "is not an MX record. MX expected";
						continue;
					}

					MailExchangeResourceRecord dnsRecord = (MailExchangeResourceRecord)mRecord;

					// get the A records for the MX record and run those by ip address
					string mx = dnsRecord.ExchangeDomainName.ToString ();

					if (string.IsNullOrEmpty (mx)) {
						resp.Message = "exchange domain name for '" + dnsRecord.Name.ToString () + "' is null";
						goto crapdomain;
					}

					mx = mx.ToLower ();

					Task<IResponse> aResponse = GetAnswersAsync (mx, RecordType.A, dnsServer: dnsIp);
					aResponse.Wait ();

					if (aResponse == null || aResponse.Result == null) {
						Console.WriteLine ("(A against dns '" + dnsIp + "' fail for '" + domain + "') ");
						resp.Message = "A against dns '" + dnsIp + "' fail for '" + domain + "'";
						continue;
					}

					if (aResponse.Result.ResponseCode == ResponseCode.NameError) {
						Console.WriteLine ("(name error for '" + domain + "' with dns '" + dnsIp + "') ");
						resp.Message = "name error for '" + domain + "' with dns '" + dnsIp + "'";
						continue;
					}

					IList<IResourceRecord> aRecords = aResponse.Result.AnswerRecords;

					if (records == null || records.Count == 0) {
						Console.WriteLine ("(no A records found for '" + mx + "' with dns '" + dnsIp + "') ");
						resp.Message = "no A records found for '" + mx + "' with dns '" + dnsIp + "'";
						continue;
					}

					foreach (IResourceRecord iRecord in aRecords) {

						if (!(iRecord is IPAddressResourceRecord)) {
							resp.Message = iRecord.Name.ToString () + " is expecting IP Address Resource Record. this is not that";
							continue;
						}

						IPAddressResourceRecord aRecord = (IPAddressResourceRecord)iRecord;

						if (serverVerified == true) {
							break;
						}

						if (bypassDomains.ContainsKey (aRecord.Name.ToString ())) {
							Console.ForegroundColor = ConsoleColor.DarkMagenta;
							Console.WriteLine ("MX bypass " + aRecord.Name + " used");
							Console.ResetColor ();
							resp.Success = true;
							resp.Message = "Success";
							return resp;
						}

						System.Net.IPAddress ipA = aRecord.IPAddress;
						foreach (int smtpPort in smtpPorts) {
							if (HasServer (ipA, smtpPort)) {
								resp.UnderlyingGoodDomain = aRecord.Name.ToString ();
								serverVerified = true;

								// 2018-11-12 constantly having to recheck crap like google's MX records because they are not the actual domain being checked
								// i will be adding successful hits to bypass domains
								// on long-running processes this will increase the memory footprint, but this is just slow and unnecessary as-is
								Console.ForegroundColor = ConsoleColor.DarkMagenta;
								Console.WriteLine ("MX " + aRecord.Name.ToString () + " added to bypass domains");
								Console.ResetColor ();
								AddBypassDomain (aRecord.Name.ToString ());

								break;
							} else {
								Console.WriteLine ("(hasServer 1 : mx doesn't have real server behind it : " + dnsRecord.Name + " - " + ipA.ToString () + ") ");
							}
						}
					}


					if (serverVerified) {
						break;
					}
				}

			// likely a typo. 'yahop.com' was one that inspired this
			crapdomain:

				if (serverVerified) {
					// get out of here. success!
					realResponse = true;
					break;
				}


				if (realResponse) {
					break;
				}
			}

			resp.Success = realResponse;
			if (resp.Success) {
				resp.Message = "Success";
			}
			return resp;
		}

		// i've run into cases where sending in a string ip address woerked by the A record hostname did not
		public static bool HasServer (
			System.Net.IPAddress server,
			int port,
			int timeout = 10000
		) {
			System.Net.IPEndPoint ipend = new System.Net.IPEndPoint (server, port);

			Console.ForegroundColor = ConsoleColor.DarkGreen;
			Console.WriteLine ("attempting " + server.ToString () + ":" + port.ToString () + " with timeout " + timeout.ToString ());
			Console.ResetColor ();

			bool ret = false;

			System.Net.Sockets.TcpClient sock = null;
			try {
				sock = new System.Net.Sockets.TcpClient (ipend.Address.ToString (), ipend.Port);
			} catch (Exception oops) {
				Console.ForegroundColor = ConsoleColor.DarkGray;
				Console.WriteLine ("unable to create socket at " + ipend.ToString ());
				Console.WriteLine ("reason : " + oops.ToString ());
				Console.ResetColor ();
				return ret;
			}
			//2010 05 23 janos
			//satx.rr.com did not respond to the telnet within the one second timeout, presumably to slow down bots
			//so i have increased this to 2000 from 1000
			// 2016 10 12 golrb.com being problematic. increasing timeout
			sock.ReceiveTimeout = timeout;
			using (System.Net.Sockets.NetworkStream ns = sock.GetStream ()) {
				byte[] data = new byte[1024];

				// for some reason a random human time here while debugging typically means a failure gets a successful response
				Random random = new Random (DateTime.Now.Second);
				int waitrand = random.Next (2000, 8000);
				Console.WriteLine ("waiting " + waitrand.ToString () + "ms to read bytes from server");
				System.Threading.Thread.Sleep (waitrand);

				try {
					int recv = ns.Read (data, 0, data.Length);
					string asciidata = System.Text.ASCIIEncoding.ASCII.GetString (data);
					Console.WriteLine ("Data received : " + asciidata);
					if (!string.IsNullOrEmpty (asciidata) && asciidata.ToLower ().Contains ("connection refused")) {
						Console.WriteLine ("connection refused! no good");
						return false;
					}
					ret = true;
				} catch (Exception oops) {
					Console.ForegroundColor = ConsoleColor.DarkGray;
					Console.WriteLine ("Error getting stream : " + oops.ToString ());
					Console.WriteLine ("-".PadRight (50, '-'));
					Console.ResetColor ();
				}
			}

			return ret;
		}

		public static void AddDns (string dnsIp) {
			if (string.IsNullOrEmpty (dnsIp)) {
				return;
			}
			if (!dnsIps.Contains (dnsIp)) {
				dnsIps.Add (dnsIp);
			}
		}

		public static void AddBypassDomain (string bypassDomain) {
			if (string.IsNullOrEmpty (bypassDomain)) {
				return;
			}
			if (!bypassDomains.ContainsKey (bypassDomain)) {
				bypassDomains.Add (bypassDomain, 0);
			}
		}

		public int DnsIpCount {
			get {
				return dnsIps.Count;
			}
		}

		public int BypassDomainCount {
			get {
				return bypassDomains.Count;
			}
		}

		private static List<string> dnsIps = new List<string> ();
		private static Dictionary<string, int> bypassDomains = new Dictionary<string, int> (); // just using dictionary for speed if this grows
		private static List<int> smtpPorts = new List<int> ();
	}
}