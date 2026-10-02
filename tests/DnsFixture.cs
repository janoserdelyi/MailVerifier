using Xunit;

namespace MailVerifier.Tests;

// all test classes share this collection so they run sequentially,
// avoiding races on the static _dnsIps / _bypassDomains lists
[CollectionDefinition ("Dns")]
public class DnsGroup : ICollectionFixture<DnsFixture> { }

public class DnsFixture
{
	public DnsFixture () {
		Verify.AddDns ("1.1.1.1");
		Verify.AddDns ("8.8.8.8");
	}
}
