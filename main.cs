public  string Encrypt(string text, string key)
    {
        var data = Encoding.UTF8.GetBytes(text);

        using (var md5 = new MD5CryptoServiceProvider())
        {
            var keys = md5.ComputeHash(Encoding.UTF8.GetBytes(key));
            using (var tripDes = new TripleDESCryptoServiceProvider { Key = keys, Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 })
            {
                var transform = tripDes.CreateEncryptor();
                var results = transform.TransformFinalBlock(data, 0, data.Length);
                return Convert.ToBase64String(results, 0, results.Length).Replace("/", "-").Replace("+", "_").Replace("=", "^").Replace("&", ".");
            }
        }
    }

    public string Decrypt(string cipher, string key)
    {
        string cipherEncoding = cipher.ToString().Replace("-", "/").Replace("_", "+").Replace("^", "=").Replace(".", "&");

        var data = Convert.FromBase64String(cipherEncoding);
        using (var md5 = new MD5CryptoServiceProvider())
        {
            var keys = md5.ComputeHash(Encoding.UTF8.GetBytes(key));
                            
            using (var tripDes = new TripleDESCryptoServiceProvider()
            {
                Key = keys, Mode = CipherMode.ECB, Padding = PaddingMode.PKCS7 })
                {
                    var transform = tripDes.CreateDecryptor();
                    var results = transform.TransformFinalBlock(data, 0, data.Length);
                    return Encoding.UTF8.GetString(results);
                }
        }
    
    }
