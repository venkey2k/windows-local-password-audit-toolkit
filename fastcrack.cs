using System;
using System.Text;

class FastCrack
{
    static uint F(uint x, uint y, uint z) { return (x & y) | (~x & z); }
    static uint G(uint x, uint y, uint z) { return (x & y) | (x & z) | (y & z); }
    static uint H(uint x, uint y, uint z) { return x ^ y ^ z; }
    static uint R(uint x, int n) { return (x << n) | (x >> (32 - n)); }

    [ThreadStatic] static byte[] buf;
    static byte[] target = new byte[16];
    [ThreadStatic] static uint[] X;

    static void Md4(string s, byte[] out16)
    {
        int len = s.Length * 2;
        int total = ((len + 8 + 63) / 64) * 64;
        if (buf == null || buf.Length < total) buf = new byte[total];
        if (X == null) X = new uint[16];
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            buf[2 * i] = (byte)c;
            buf[2 * i + 1] = (byte)(c >> 8);
        }
        buf[len] = 0x80;
        for (int i = len + 1; i < total; i++) buf[i] = 0;
        ulong bits = (ulong)len * 8UL;
        for (int i = 0; i < 8; i++) buf[total - 8 + i] = (byte)(bits >> (8 * i));

        uint a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

        for (int off = 0; off < total; off += 64)
        {
            for (int j = 0; j < 16; j++)
                X[j] = (uint)(buf[off + 4 * j] | (buf[off + 4 * j + 1] << 8) | (buf[off + 4 * j + 2] << 16) | (buf[off + 4 * j + 3] << 24));

            uint a = a0, b = b0, c = c0, d = d0;

            a = R(a + F(b, c, d) + X[0], 3);  d = R(d + F(a, b, c) + X[1], 7);
            c = R(c + F(d, a, b) + X[2], 11); b = R(b + F(c, d, a) + X[3], 19);
            a = R(a + F(b, c, d) + X[4], 3);  d = R(d + F(a, b, c) + X[5], 7);
            c = R(c + F(d, a, b) + X[6], 11); b = R(b + F(c, d, a) + X[7], 19);
            a = R(a + F(b, c, d) + X[8], 3);  d = R(d + F(a, b, c) + X[9], 7);
            c = R(c + F(d, a, b) + X[10], 11); b = R(b + F(c, d, a) + X[11], 19);
            a = R(a + F(b, c, d) + X[12], 3); d = R(d + F(a, b, c) + X[13], 7);
            c = R(c + F(d, a, b) + X[14], 11); b = R(b + F(c, d, a) + X[15], 19);

            a = R(a + G(b, c, d) + X[0] + 0x5A827999, 3);  d = R(d + G(a, b, c) + X[4] + 0x5A827999, 5);
            c = R(c + G(d, a, b) + X[8] + 0x5A827999, 9);  b = R(b + G(c, d, a) + X[12] + 0x5A827999, 13);
            a = R(a + G(b, c, d) + X[1] + 0x5A827999, 3);  d = R(d + G(a, b, c) + X[5] + 0x5A827999, 5);
            c = R(c + G(d, a, b) + X[9] + 0x5A827999, 9);  b = R(b + G(c, d, a) + X[13] + 0x5A827999, 13);
            a = R(a + G(b, c, d) + X[2] + 0x5A827999, 3);  d = R(d + G(a, b, c) + X[6] + 0x5A827999, 5);
            c = R(c + G(d, a, b) + X[10] + 0x5A827999, 9); b = R(b + G(c, d, a) + X[14] + 0x5A827999, 13);
            a = R(a + G(b, c, d) + X[3] + 0x5A827999, 3);  d = R(d + G(a, b, c) + X[7] + 0x5A827999, 5);
            c = R(c + G(d, a, b) + X[11] + 0x5A827999, 9); b = R(b + G(c, d, a) + X[15] + 0x5A827999, 13);

            a = R(a + H(b, c, d) + X[0] + 0x6ED9EBA1, 3);  d = R(d + H(a, b, c) + X[8] + 0x6ED9EBA1, 9);
            c = R(c + H(d, a, b) + X[4] + 0x6ED9EBA1, 11); b = R(b + H(c, d, a) + X[12] + 0x6ED9EBA1, 15);
            a = R(a + H(b, c, d) + X[2] + 0x6ED9EBA1, 3);  d = R(d + H(a, b, c) + X[10] + 0x6ED9EBA1, 9);
            c = R(c + H(d, a, b) + X[6] + 0x6ED9EBA1, 11); b = R(b + H(c, d, a) + X[14] + 0x6ED9EBA1, 15);
            a = R(a + H(b, c, d) + X[1] + 0x6ED9EBA1, 3);  d = R(d + H(a, b, c) + X[9] + 0x6ED9EBA1, 9);
            c = R(c + H(d, a, b) + X[5] + 0x6ED9EBA1, 11); b = R(b + H(c, d, a) + X[13] + 0x6ED9EBA1, 15);
            a = R(a + H(b, c, d) + X[3] + 0x6ED9EBA1, 3);  d = R(d + H(a, b, c) + X[11] + 0x6ED9EBA1, 9);
            c = R(c + H(d, a, b) + X[7] + 0x6ED9EBA1, 11); b = R(b + H(c, d, a) + X[15] + 0x6ED9EBA1, 15);

            a0 += a; b0 += b; c0 += c; d0 += d;
        }

        Put(out16, 0, a0); Put(out16, 4, b0); Put(out16, 8, c0); Put(out16, 12, d0);
    }

    static void Put(byte[] o, int i, uint v)
    {
        o[i] = (byte)v; o[i + 1] = (byte)(v >> 8); o[i + 2] = (byte)(v >> 16); o[i + 3] = (byte)(v >> 24);
    }

    static byte[] Hash(string s)
    {
        byte[] h = new byte[16];
        Md4(s, h);
        return h;
    }

    static string Hex(byte[] b)
    {
        StringBuilder sb = new StringBuilder(32);
        foreach (byte x in b) sb.Append(x.ToString("x2"));
        return sb.ToString();
    }

    static int Selftest()
    {
        bool ok =
            Hex(Hash("")) == "31d6cfe0d16ae931b73c59d7e0c089c0" &&
            Hex(Hash("password")) == "8846f7eaee8fb117ad06bdd830b7586c" &&
            Hex(Hash("Password1")) == Hex(Hash("Password1"));
        if (!ok) { Console.Out.WriteLine("selftest FAIL"); return 1; }
        Console.Out.WriteLine("selftest PASS");
        Console.Out.WriteLine("password = " + Hex(Hash("password")));
        return 0;
    }

    static volatile bool foundFlag = false;
    static string foundPw = null;

    static void ParseTarget(string t)
    {
        t = t.Trim().ToLowerInvariant();
        for (int i = 0; i < 16; i++) target[i] = Convert.ToByte(t.Substring(i * 2, 2), 16);
    }

    static bool Equal(byte[] h)
    {
        for (int i = 0; i < 16; i++) if (h[i] != target[i]) return false;
        return true;
    }

    static int Sweep(string t, string wordsCsv, string sepsCsv, int maxDigits)
    {
        ParseTarget(t);
        string[] words = wordsCsv.Split(',');
        string[] seps = sepsCsv.Split(new char[] { ',' }, StringSplitOptions.None);

        var pairs = new System.Collections.Generic.List<string[]>();
        foreach (var w0 in words)
        {
            string lw = w0.Trim().ToLowerInvariant();
            if (lw.Length == 0) continue;
            string[] forms = new string[] { lw, char.ToUpper(lw[0]) + lw.Substring(1), lw.ToUpperInvariant() };
            foreach (var f in forms)
            {
                foreach (var s in seps)
                {
                    pairs.Add(new string[] { f + s, "" });
                    pairs.Add(new string[] { "", s + f });
                }
            }
        }

        var plist = pairs.ToArray();
        long tried = 0;
        var sw = System.Diagnostics.Stopwatch.StartNew();

        for (int width = 1; width <= maxDigits && !foundFlag; width++)
        {
            long limit = 1;
            for (int i = 0; i < width; i++) limit *= 10;
            int w = width;

            System.Threading.Tasks.Parallel.For(0, plist.Length, pi =>
            {
                if (foundFlag) return;
                string pre = plist[pi][0];
                string post = plist[pi][1];
                byte[] h = new byte[16];
                StringBuilder sb = new StringBuilder(64);
                for (long d = 0; d < limit; d++)
                {
                    if (foundFlag) return;
                    sb.Length = 0;
                    sb.Append(pre);
                    string ds = d.ToString();
                    for (int k = ds.Length; k < w; k++) sb.Append('0');
                    sb.Append(ds);
                    sb.Append(post);
                    string c = sb.ToString();
                    Md4(c, h);
                    if (Equal(h))
                    {
                        foundPw = c;
                        foundFlag = true;
                        return;
                    }
                }
            });

            tried += limit * plist.Length;
            Console.Error.WriteLine("width\t" + width + "\ttried\t" + tried + "\tsec\t" + sw.Elapsed.TotalSeconds.ToString("F1"));
        }

        if (foundFlag)
        {
            Console.Out.WriteLine("MATCH\t" + foundPw);
            return 0;
        }
        Console.Error.WriteLine("done\t" + tried);
        return 2;
    }

    static string[] Variants(string w)
    {
        var list = new System.Collections.Generic.List<string>(24);
        list.Add(w);
        string lw = w.ToLowerInvariant();
        if (lw != w) list.Add(lw);
        list.Add(w.ToUpperInvariant());
        if (lw.Length > 0) list.Add(char.ToUpper(lw[0]) + lw.Substring(1));
        string[] sufs = { "1", "12", "123", "1234", "12345", "!", "@", "#", "2024", "2025", "2026", "007", "69", "86", "68", "8668", "!@#", "@123" };
        int baseCount = list.Count;
        for (int i = 0; i < baseCount; i++)
        {
            string b = list[i];
            foreach (var s in sufs) list.Add(b + s);
        }
        list.Add(lw.Replace("a", "4").Replace("e", "3").Replace("i", "1").Replace("o", "0").Replace("s", "5"));
        list.Add(lw.Replace("a", "@").Replace("e", "3").Replace("i", "1").Replace("o", "0").Replace("s", "$"));
        list.Add(lw + lw);
        return list.ToArray();
    }

    static int DictMode(string t, string path)
    {
        ParseTarget(t);
        string[] lines = System.IO.File.ReadAllLines(path);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        System.Threading.Tasks.Parallel.ForEach(lines, (line, state) =>
        {
            if (foundFlag) { state.Stop(); return; }
            string w = line.Trim();
            if (w.Length == 0 || w.Length > 40) return;
            foreach (var cand in Variants(w))
            {
                byte[] h = new byte[16];
                Md4(cand, h);
                if (Equal(h))
                {
                    foundPw = cand;
                    foundFlag = true;
                    state.Stop();
                    return;
                }
            }
        });
        Console.Error.WriteLine("done\tdict\t" + lines.Length + "\tsec\t" + sw.Elapsed.TotalSeconds.ToString("F1"));
        if (foundFlag) { Console.Out.WriteLine("MATCH\t" + foundPw); return 0; }
        return 2;
    }


    static System.Collections.Generic.List<string> CaseVariants(string w)
    {
        var res = new System.Collections.Generic.List<string>();
        var idx = new System.Collections.Generic.List<int>();
        for (int i = 0; i < w.Length; i++) if (char.IsLetter(w[i])) idx.Add(i);
        if (idx.Count > 9) idx.RemoveRange(9, idx.Count - 9);
        int combos = 1 << idx.Count;
        if (combos > 512) combos = 512;
        for (int mask = 0; mask < combos; mask++)
        {
            var ch = w.ToCharArray();
            for (int b = 0; b < idx.Count; b++)
                ch[idx[b]] = ((mask >> b) & 1) == 1 ? char.ToUpper(w[idx[b]]) : char.ToLower(w[idx[b]]);
            res.Add(new string(ch));
        }
        return res;
    }

    static bool Check(string cand, byte[] h)
    {
        Md4(cand, h);
        if (Equal(h)) { foundPw = cand; foundFlag = true; return true; }
        return false;
    }

    static int Hybrid(string t, string basesCsv, string charset, int maxLen)
    {
        ParseTarget(t);
        var jobs = new System.Collections.Generic.List<string>();
        foreach (var b0 in basesCsv.Split(','))
        {
            string b = b0.Trim().ToLowerInvariant();
            if (b.Length == 0 || b.Length > maxLen) continue;
            foreach (var cv in CaseVariants(b)) jobs.Add(cv);
        }
        var sw = System.Diagnostics.Stopwatch.StartNew();
        long counter = 0;

        System.Threading.Tasks.Parallel.ForEach(jobs, (v, state) =>
        {
            if (foundFlag) { state.Stop(); return; }
            byte[] h = new byte[16];
            System.Collections.Generic.List<string> cb = new System.Collections.Generic.List<string>();
            int room = maxLen - v.Length;

            if (Check(v, h)) { state.Stop(); return; }

            int cl = charset.Length;
            for (int pos = 0; pos <= v.Length && room >= 1; pos++)
                for (int a = 0; a < cl; a++)
                    cb.Add(v.Insert(pos, charset[a].ToString()));

            if (room >= 2)
                for (int pos = 0; pos <= v.Length; pos++)
                    for (int a = 0; a < cl; a++)
                        for (int b2 = 0; b2 < cl; b2++)
                            cb.Add(v.Insert(pos, new string(new char[] { charset[a], charset[b2] })));

            if (room >= 3)
            {
                for (int a = 0; a < cl; a++)
                    for (int b2 = 0; b2 < cl; b2++)
                        for (int c2 = 0; c2 < cl; c2++)
                        {
                            string x = new string(new char[] { charset[a], charset[b2], charset[c2] });
                            cb.Add(v + x);
                            cb.Add(x + v);
                        }
            }

            foreach (var cand in cb)
            {
                if (foundFlag) { state.Stop(); return; }
                System.Threading.Interlocked.Increment(ref counter);
                if (cand.Length > maxLen) continue;
                if (Check(cand, h)) { state.Stop(); return; }
            }
        });

        Console.Error.WriteLine("done\thybrid\t" + counter + "\tsec\t" + sw.Elapsed.TotalSeconds.ToString("F1"));
        if (foundFlag) { Console.Out.WriteLine("MATCH\t" + foundPw); return 0; }
        return 2;
    }

    static void Md4(char[] s, int slen, byte[] out16)
    {
        int len = slen * 2;
        int total = ((len + 8 + 63) / 64) * 64;
        if (buf == null || buf.Length < total) buf = new byte[total];
        if (X == null) X = new uint[16];
        for (int i = 0; i < slen; i++)
        {
            char c = s[i];
            buf[2 * i] = (byte)c;
            buf[2 * i + 1] = (byte)(c >> 8);
        }
        buf[len] = 0x80;
        for (int i = len + 1; i < total; i++) buf[i] = 0;
        ulong bits = (ulong)len * 8UL;
        for (int i = 0; i < 8; i++) buf[total - 8 + i] = (byte)(bits >> (8 * i));

        uint a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
        for (int off = 0; off < total; off += 64)
        {
            for (int j = 0; j < 16; j++)
                X[j] = (uint)(buf[off + 4 * j] | (buf[off + 4 * j + 1] << 8) | (buf[off + 4 * j + 2] << 16) | (buf[off + 4 * j + 3] << 24));
            uint a = a0, b = b0, c = c0, d = d0;

            a = R(a + F(b, c, d) + X[0], 3);  d = R(d + F(a, b, c) + X[1], 7);
            c = R(c + F(d, a, b) + X[2], 11); b = R(b + F(c, d, a) + X[3], 19);
            a = R(a + F(b, c, d) + X[4], 3);  d = R(d + F(a, b, c) + X[5], 7);
            c = R(c + F(d, a, b) + X[6], 11); b = R(b + F(c, d, a) + X[7], 19);
            a = R(a + F(b, c, d) + X[8], 3);  d = R(d + F(a, b, c) + X[9], 7);
            c = R(c + F(d, a, b) + X[10], 11); b = R(b + F(c, d, a) + X[11], 19);
            a = R(a + F(b, c, d) + X[12], 3); d = R(d + F(a, b, c) + X[13], 7);
            c = R(c + F(d, a, b) + X[14], 11); b = R(b + F(c, d, a) + X[15], 19);

            a = R(a + G(b, c, d) + X[0] + 0x5A827999, 3);  d = R(d + G(a, b, c) + X[4] + 0x5A827999, 5);
            c = R(c + G(d, a, b) + X[8] + 0x5A827999, 9);  b = R(b + G(c, d, a) + X[12] + 0x5A827999, 13);
            a = R(a + G(b, c, d) + X[1] + 0x5A827999, 3);  d = R(d + G(a, b, c) + X[5] + 0x5A827999, 5);
            c = R(c + G(d, a, b) + X[9] + 0x5A827999, 9);  b = R(b + G(c, d, a) + X[13] + 0x5A827999, 13);
            a = R(a + G(b, c, d) + X[2] + 0x5A827999, 3);  d = R(d + G(a, b, c) + X[6] + 0x5A827999, 5);
            c = R(c + G(d, a, b) + X[10] + 0x5A827999, 9); b = R(b + G(c, d, a) + X[14] + 0x5A827999, 13);
            a = R(a + G(b, c, d) + X[3] + 0x5A827999, 3);  d = R(d + G(a, b, c) + X[7] + 0x5A827999, 5);
            c = R(c + G(d, a, b) + X[11] + 0x5A827999, 9); b = R(b + G(c, d, a) + X[15] + 0x5A827999, 13);

            a = R(a + H(b, c, d) + X[0] + 0x6ED9EBA1, 3);  d = R(d + H(a, b, c) + X[8] + 0x6ED9EBA1, 9);
            c = R(c + H(d, a, b) + X[4] + 0x6ED9EBA1, 11); b = R(b + H(c, d, a) + X[12] + 0x6ED9EBA1, 15);
            a = R(a + H(b, c, d) + X[2] + 0x6ED9EBA1, 3);  d = R(d + H(a, b, c) + X[10] + 0x6ED9EBA1, 9);
            c = R(c + H(d, a, b) + X[6] + 0x6ED9EBA1, 11); b = R(b + H(c, d, a) + X[14] + 0x6ED9EBA1, 15);
            a = R(a + H(b, c, d) + X[1] + 0x6ED9EBA1, 3);  d = R(d + H(a, b, c) + X[9] + 0x6ED9EBA1, 9);
            c = R(c + H(d, a, b) + X[5] + 0x6ED9EBA1, 11); b = R(b + H(c, d, a) + X[13] + 0x6ED9EBA1, 15);
            a = R(a + H(b, c, d) + X[3] + 0x6ED9EBA1, 3);  d = R(d + H(a, b, c) + X[11] + 0x6ED9EBA1, 9);
            c = R(c + H(d, a, b) + X[7] + 0x6ED9EBA1, 11); b = R(b + H(c, d, a) + X[15] + 0x6ED9EBA1, 15);

            a0 += a; b0 += b; c0 += c; d0 += d;
        }
        Put(out16, 0, a0); Put(out16, 4, b0); Put(out16, 8, c0); Put(out16, 12, d0);
    }

    static int Brute(string t, string charset, int maxLen)
    {
        ParseTarget(t);
        char[] cs = charset.ToCharArray();
        int n = cs.Length;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        long done = 0;
        for (int len = 1; len <= maxLen && !foundFlag; len++)
        {
            long total = 1; for (int i = 0; i < len; i++) total *= n;
            int L = len;
            System.Threading.Tasks.Parallel.For(0, n, (first, state) =>
            {
                if (foundFlag) { state.Stop(); return; }
                byte[] h = new byte[16];
                char[] buf2 = new char[L];
                buf2[0] = cs[first];
                int[] d = new int[L];
                long rest = total / n;
                for (long k = 0; k < rest; k++)
                {
                    if (foundFlag) { state.Stop(); return; }
                    for (int p = 1; p < L; p++) buf2[p] = cs[d[p]];
                    Md4(buf2, L, h);
                    if (Equal(h)) { foundPw = new string(buf2); foundFlag = true; state.Stop(); return; }
                    for (int p = L - 1; p >= 1; p--) { if (++d[p] < n) break; d[p] = 0; }
                }
            });
            done += total;
            Console.Error.WriteLine("len\t" + len + "\ttotal\t" + done + "\tsec\t" + sw.Elapsed.TotalSeconds.ToString("F1"));
        }
        Console.Error.WriteLine("done\tbrute\t" + done + "\tsec\t" + sw.Elapsed.TotalSeconds.ToString("F1"));
        if (foundFlag) { Console.Out.WriteLine("MATCH\t" + foundPw); return 0; }
        return 2;
    }
    static int Main(string[] args)
    {
        if (args.Length >= 1 && args[0] == "--selftest") return Selftest();

        if (args.Length >= 4 && args[1] == "brute") return Brute(args[0], args[2], int.Parse(args[3]));
        if (args.Length >= 5 && args[1] == "hybrid") return Hybrid(args[0], args[2], args[3], int.Parse(args[4]));
        if (args.Length >= 3 && args[1] == "dict") return DictMode(args[0], args[2]);
        if (args.Length >= 5 && args[1] == "sweep")
            return Sweep(args[0], args[2], args[3], int.Parse(args[4]));

        if (args.Length < 1) { Console.Error.WriteLine("usage: fastcrack <ntlm-hex>  (candidates on stdin)"); return 1; }

        ParseTarget(args[0]);

        byte[] h = new byte[16];
        string line;
        long n = 0;
        while ((line = Console.In.ReadLine()) != null)
        {
            Md4(line, h);
            n++;
            if (Equal(h))
            {
                Console.Out.WriteLine("MATCH\t" + line);
                Console.Out.Flush();
                Console.Error.WriteLine("tried\t" + n);
                return 0;
            }
        }
        Console.Error.WriteLine("done\t" + n);
        return 2;
    }
}
