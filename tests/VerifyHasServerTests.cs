using System.Net;
using System.Threading.Tasks;
using Xunit;

namespace MailVerifier.Tests;

[Collection ("Dns")]
public class VerifyHasServerTests
{
	// Google's public MX hosts reliably answer on port 25; tests may fail on networks that block outbound SMTP
	public static TheoryData<string, int> KnownSmtpHosts { get; } = new ()
	{
		{ "gmail-smtp-in.l.google.com", 25 },
		{ "aspmx.l.google.com", 25 },
	};

	[Theory]
	[MemberData (nameof (KnownSmtpHosts))]
	public async Task HasServer_KnownSmtpServer_ReturnsTrue (string hostname, int port) {
		var addresses = await Dns.GetHostAddressesAsync (hostname);
		var result = await Verify.HasServer (addresses[0], port);
		Assert.True (result);
	}

	[Theory]
	[InlineData ("127.0.0.1", 12345)]
	[InlineData ("127.0.0.1", 23456)]
	public async Task HasServer_LoopbackUnusedPort_ReturnsFalse (string ip, int port) {
		var address = IPAddress.Parse (ip);
		// connection refused is immediate, so the full HasServer delay does not apply
		var result = await Verify.HasServer (address, port, timeout: 3000);
		Assert.False (result);
	}
}
