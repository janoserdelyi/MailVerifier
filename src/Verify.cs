using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

using System.Threading.Tasks;
using DNS.Client;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

namespace MailVerifier;

public class Verify
{
	// 2018-12-06 get mx record domains
	public static IList<string> GetMxDomains (
		string address
	) {
		return GetMxDomainsAsync (address).GetAwaiter ().GetResult ();
	}

	public static async Task<IList<string>> GetMxDomainsAsync (
		string address
	) {
		ArgumentNullException.ThrowIfNull (address, "an email address is required");

		if (!address.Contains ('@')) {
			throw new ArgumentException ("this is clearly not an email address");
		}

		if (address.Length < 6) {
			throw new ArgumentException ("this is not an email address, try again");
		}

		address = address.ToLowerInvariant ().Trim ();
		string domain = address.Split ('@')[1];

		if (_dnsIps.IsEmpty) {
			throw new ArgumentException ("Please supply DNS ip's to use for this check");
		}

		var mxs = new List<string> ();

		foreach (string dnsIp in _dnsIps.Keys) {
			if (WriteDebugMessages) {
				Console.ForegroundColor = ConsoleColor.DarkGray;
				Console.WriteLine ("attempting to resolve DNS for " + domain + "... with dns server " + dnsIp);
				Console.ResetColor ();
			}

			IResponse resp = null;
			try {
				resp = await GetAnswersAsync (domain, RecordType.MX, dnsServer: dnsIp);
			} catch (Exception oops) {
				if (WriteDebugMessages) {
					Console.WriteLine ("(MX failure against dns '" + dnsIp + "' for '" + domain + "') ");
					Console.WriteLine (oops.ToString ());
				}

				continue;
			}

			if (resp == null) {
				if (WriteDebugMessages) {
					Console.WriteLine ("(MX name failure against dns '" + dnsIp + "' for '" + domain + "') ");
				}

				continue;
			}

			if (resp.ResponseCode == ResponseCode.NameError) {
				if (WriteDebugMessages) {
					Console.WriteLine ("(name error for '" + domain + "' with dns '" + dnsIp + "') ");
				}

				continue;
			}

			IList<IResourceRecord> records = resp.AnswerRecords;

			if (records == null || records.Count == 0) {
				Console.WriteLine ("(no MX records found for '" + domain + "' with dns '" + dnsIp + "') ");
				continue;
			}

			foreach (var record in records) {
				string mx = ((MailExchangeResourceRecord)record).ExchangeDomainName.ToString ();
				if (string.IsNullOrEmpty (mx)) {
					continue;
				}

				mx = mx.ToLowerInvariant ();
				if (!mxs.Contains (mx)) {
					mxs.Add (mx);
				}
			}
		}

		return mxs;
	}

	public static async Task<IResponse> GetAnswersAsync (
		string domain,
		RecordType recordType,
		string dnsServer = "1.1.1.1",
		bool configureAwait = false
	) {
		var request = new ClientRequest (dnsServer);

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

	public static async Task<Response> Check (
		string address,
		int timeout = 10000
	) {
		ArgumentNullException.ThrowIfNull (address, "an email address is required");

		if (!address.Contains ('@')) {
			throw new ArgumentException ("this is clearly not an email address");
		}

		if (address.Length < 6) {
			throw new ArgumentException ("this is not an email address, try again");
		}

		address = address.ToLowerInvariant ().Trim ();
		string domain = address.Split ('@')[1];

		if (_dnsIps.IsEmpty) {
			throw new ArgumentException ("Please supply DNS ip's to use for this check");
		}

		var resp = new Response {
			Address = address,
			Domain = domain,
			Success = false,
			Message = ""
		};

		if (_bypassDomains.ContainsKey (domain)) {
			resp.Success = true;
			resp.Message = "Success";
			return resp;
		}

		if (_smtpPorts.IsEmpty) {
			_smtpPorts.TryAdd (25, 0);
			_smtpPorts.TryAdd (587, 0);
		}

		bool realResponse = false;

		if (WriteDebugMessages) {
			Console.ForegroundColor = ConsoleColor.Green;
			Console.WriteLine ("USING NEW LIBRARY");
			Console.ResetColor ();
		}

		foreach (string dnsIp in _dnsIps.Keys) {

			if (WriteDebugMessages) {
				Console.ForegroundColor = ConsoleColor.DarkGray;
				Console.WriteLine ("attempting to resolve DNS for " + domain + "... with dns server " + dnsIp);
				Console.ResetColor ();
			}

			IResponse mxResponse = null;
			try {
				mxResponse = await GetAnswersAsync (domain, RecordType.MX, dnsServer: dnsIp);
			} catch (Exception oops) {
				if (WriteDebugMessages) {
					Console.WriteLine ("(MX against dns '" + dnsIp + "' fail for '" + domain + "') ");
					Console.WriteLine (oops.ToString ());
				}

				resp.Message = "Error determining MX at dns '" + dnsIp + "' for '" + domain + "'";
				continue;
			}

			if (mxResponse == null) {
				if (WriteDebugMessages) {
					Console.WriteLine ("(MX against dns '" + dnsIp + "' fail for '" + domain + "') ");
				}

				resp.Message = "MX not found at dns '" + dnsIp + "' for '" + domain + "'";
				continue;
			}

			if (mxResponse.ResponseCode == ResponseCode.NameError) {
				if (WriteDebugMessages) {
					Console.WriteLine ("(name error for '" + domain + "' with dns '" + dnsIp + "') ");
				}

				resp.Message = "name error for '" + domain + "'";
				continue;
			}

			IList<IResourceRecord> records = mxResponse.AnswerRecords;

			if (records == null || records.Count == 0) {
				if (WriteDebugMessages) {
					Console.WriteLine ("(no MX records found for '" + domain + "' with dns '" + dnsIp + "') ");
				}

				resp.Message = "no MX records for '" + domain + "'";
				continue;
			}

			bool serverVerified = false;

			foreach (IResourceRecord mRecord in records) {

				if (!(mRecord is MailExchangeResourceRecord)) {
					resp.Message = mRecord.Name.ToString () + "is not an MX record. MX expected";
					continue;
				}

				var dnsRecord = (MailExchangeResourceRecord)mRecord;

				// get the A records for the MX record and run those by ip address
				string mx = dnsRecord.ExchangeDomainName.ToString ();

				if (string.IsNullOrEmpty (mx)) {
					resp.Message = "exchange domain name for '" + dnsRecord.Name.ToString () + "' is null";
					goto crapdomain;
				}

				mx = mx.ToLowerInvariant ();

				IResponse aResponse = await GetAnswersAsync (mx, RecordType.A, dnsServer: dnsIp);

				if (aResponse == null) {
					if (WriteDebugMessages) {
						Console.WriteLine ("(A against dns '" + dnsIp + "' fail for '" + domain + "') ");
					}

					resp.Message = "A against dns '" + dnsIp + "' fail for '" + domain + "'";
					continue;
				}

				if (aResponse.ResponseCode == ResponseCode.NameError) {
					if (WriteDebugMessages) {
						Console.WriteLine ("(name error for '" + domain + "' with dns '" + dnsIp + "') ");
					}

					resp.Message = "name error for '" + domain + "' with dns '" + dnsIp + "'";
					continue;
				}

				IList<IResourceRecord> aRecords = aResponse.AnswerRecords;

				if (records == null || records.Count == 0) {
					if (WriteDebugMessages) {
						Console.WriteLine ("(no A records found for '" + mx + "' with dns '" + dnsIp + "') ");
					}

					resp.Message = "no A records found for '" + mx + "' with dns '" + dnsIp + "'";
					continue;
				}

				foreach (IResourceRecord iRecord in aRecords) {

					if (!(iRecord is IPAddressResourceRecord)) {
						resp.Message = iRecord.Name.ToString () + " is expecting IP Address Resource Record. this is not that";
						continue;
					}

					var aRecord = (IPAddressResourceRecord)iRecord;

					if (serverVerified == true) {
						break;
					}

					if (_bypassDomains.ContainsKey (aRecord.Name.ToString ())) {
						if (WriteDebugMessages) {
							Console.ForegroundColor = ConsoleColor.DarkMagenta;
							Console.WriteLine ("MX bypass " + aRecord.Name + " used");
							Console.ResetColor ();
						}

						resp.Success = true;
						resp.Message = "Success";
						return resp;
					}

					System.Net.IPAddress ipA = aRecord.IPAddress;
					foreach (int smtpPort in _smtpPorts.Keys) {
						if (await HasServer (ipA, smtpPort, timeout)) {
							resp.UnderlyingGoodDomain = aRecord.Name.ToString ();
							serverVerified = true;

							// 2018-11-12 constantly having to recheck crap like google's MX records because they are not the actual domain being checked
							// i will be adding successful hits to bypass domains
							// on long-running processes this will increase the memory footprint, but this is just slow and unnecessary as-is
							if (WriteDebugMessages) {
								Console.ForegroundColor = ConsoleColor.DarkMagenta;
								Console.WriteLine ("MX " + aRecord.Name.ToString () + " added to bypass domains");
								Console.ResetColor ();
							}

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
	public static async Task<bool> HasServer (
		System.Net.IPAddress server,
		int port,
		int timeout = 10000
	) {
		var ipend = new System.Net.IPEndPoint (server, port);

		if (WriteDebugMessages) {
			Console.ForegroundColor = ConsoleColor.DarkGreen;
			Console.WriteLine ("attempting " + server.ToString () + ":" + port.ToString (System.Globalization.CultureInfo.InvariantCulture) + " with timeout " + timeout.ToString (System.Globalization.CultureInfo.InvariantCulture));
			Console.ResetColor ();
		}

		bool ret = false;

		System.Net.Sockets.TcpClient sock;
		try {
			sock = new System.Net.Sockets.TcpClient ();
			using var cts = new System.Threading.CancellationTokenSource (timeout);
			await sock.ConnectAsync (ipend, cts.Token);
		} catch (Exception oops) {
			if (WriteDebugMessages) {
				Console.ForegroundColor = ConsoleColor.DarkGray;
				Console.WriteLine ("unable to create socket at " + ipend.ToString ());
				Console.WriteLine ("reason : " + oops.ToString ());
				Console.ResetColor ();
			}

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
			var random = new Random (DateTime.Now.Second);
			int waitrand = random.Next (2000, 8000);
			if (WriteDebugMessages) {
				Console.WriteLine ("waiting " + waitrand.ToString (System.Globalization.CultureInfo.InvariantCulture) + "ms to read bytes from server");
			}

			await Task.Delay (waitrand);

			try {
				int recv = await ns.ReadAsync (data.AsMemory ());
				string asciidata = System.Text.Encoding.ASCII.GetString (data);
				Console.WriteLine ("Data received : " + asciidata);
				if (!string.IsNullOrEmpty (asciidata) && asciidata.ToLowerInvariant ().Contains ("connection refused", StringComparison.InvariantCultureIgnoreCase)) {
					if (WriteDebugMessages) {
						Console.WriteLine ("connection refused! no good");
					}

					return false;
				}

				ret = true;
			} catch (Exception oops) {
				if (WriteDebugMessages) {
					Console.ForegroundColor = ConsoleColor.DarkGray;
					Console.WriteLine ("Error getting stream : " + oops.ToString ());
					Console.WriteLine ("-".PadRight (50, '-'));
					Console.ResetColor ();
				}
			}
		}

		return ret;
	}

	public static void AddDns (string dnsIp) {
		if (string.IsNullOrEmpty (dnsIp)) {
			return;
		}

		_dnsIps.TryAdd (dnsIp, 0);
	}

	public static void AddBypassDomain (string bypassDomain) {
		if (string.IsNullOrEmpty (bypassDomain)) {
			return;
		}

		_bypassDomains.TryAdd (bypassDomain, 0);
	}

	public static int DnsIpCount {
		get {
			return _dnsIps.Count;
		}
	}

	public static int BypassDomainCount {
		get {
			return _bypassDomains.Count;
		}
	}

	private static readonly ConcurrentDictionary<string, byte> _dnsIps = new ();
	private static readonly ConcurrentDictionary<string, int> _bypassDomains = new ();
	private static readonly ConcurrentDictionary<int, byte> _smtpPorts = new ();
	public static bool WriteDebugMessages { get; set; }
}
