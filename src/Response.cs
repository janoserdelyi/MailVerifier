using System;

namespace MailVerifier
{
	public class Response
	{
		public Response () {

		}

		public bool Success { get; set; }
		public string Message { get; set; }
		public string Address { get; set; }
		public string Domain { get; set; }
		public string UnderlyingGoodDomain { get; set; } // a way to convey what common underlying A records behind the initial MX record is good in the response
	}
}