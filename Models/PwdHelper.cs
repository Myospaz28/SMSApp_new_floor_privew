using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Text;

namespace SMSApp.Models
{
	public class Helper
	{
		public static string Encrypt(string? password)
		{
			String encodedData = String.Empty;
			byte[] encData_byte = { };

			encData_byte = new byte[password.Length];
			encData_byte = System.Text.Encoding.UTF8.GetBytes(password);
			encodedData = Convert.ToBase64String(encData_byte);

			return encodedData;
		}

		public static string Decrypt(string? encodedData)
		{
			UTF8Encoding encoder = new System.Text.UTF8Encoding();
			Decoder utf8Decode = encoder.GetDecoder();
			byte[] todecode_byte = { };
			int charCount = 0;
			char[] decoded_char = null;
			string result = String.Empty;

			todecode_byte = Convert.FromBase64String(encodedData);
			charCount = utf8Decode.GetCharCount(todecode_byte, 0, todecode_byte.Length);

			decoded_char = new char[charCount];
			utf8Decode.GetChars(todecode_byte, 0, todecode_byte.Length, decoded_char, 0);
			result = new String(decoded_char);
			return result;
		}
	}
}