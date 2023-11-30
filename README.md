# MailVerifier

Helper library to check for MX Records on an email address to at least see if it's potentially a mail-receiving domain.

Additionally it will attempt to make a basic connection to the appropriate A record and port to see if there is a mail server behind it.

## Basic usage

```csharp

// Add DNS servers of your choice. any number. they will be tried in order in the event of failures
// so ideally only the fuirst ever gets used
MailVerifier.Verify.AddDns ("1.1.1.1");
MailVerifier.Verify.AddDns ("208.67.220.220");

// Add any bypass domains. These are domains that you don't wish to bother testing.
// This is usually because you know they are legit and it's not worth the expense of testing
MailVerifier.Verify.AddBypassDomain ("google.com");
MailVerifier.Verify.AddBypassDomain ("yahoo.com");
MailVerifier.Verify.AddBypassDomain ("live.com");

// basic usage : 
MailVerifier.Response r = null;
try {
  r = MailVerifier.Verify.Check ("someaddress@fakedomain.com");
} catch (System.ArgumentNullException oops) {
  // no email address syupplied, handle however you like
} catch (System.ArgumentException oops) {
  // some other failure, like malformed email address, no DNS servers, etc
} catch (Exception oops) {
  // other! oops.Message should tell you
}

if (r.Success == false) {
  // just because you got past exceptions doesn't mean the email domain is good
}

// you can also get MX domains in a IList<string>
var mxdomains = MailVerifier.Verify.GetMxDomains ("someaddress@fakedomain.com");

// there are some other public methods, but nothing you'd likely use as-is

```
