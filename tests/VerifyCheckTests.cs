using System.Threading.Tasks;
using Xunit;

namespace MailVerifier.Tests;

// each Check call connects to a real SMTP server and reads the banner; expect several seconds per case
[Collection ("Dns")]
public class VerifyCheckTests
{
	public static TheoryData<string> ValidEmails { get; } = new ()
	{
		"test@gmail.com",
		"test@yahoo.com",
		"test@outlook.com",
	};

	public static TheoryData<string> UnresolvableEmails { get; } = new ()
	{
		"test@nonexistent-xyz99999.invalid",
		"test@definitely-not-real-888.invalid",
	};

	[Theory]
	[MemberData (nameof (ValidEmails))]
	public async Task Check_ValidEmail_ReturnsSuccess (string address) {
		var result = await Verify.Check (address);
		Assert.True (result.Success);
		Assert.Equal ("Success", result.Message);
		Assert.Equal (address, result.Address);
	}

	[Theory]
	[MemberData (nameof (UnresolvableEmails))]
	public async Task Check_UnresolvableDomain_ReturnsFailure (string address) {
		var result = await Verify.Check (address);
		Assert.False (result.Success);
	}
}
