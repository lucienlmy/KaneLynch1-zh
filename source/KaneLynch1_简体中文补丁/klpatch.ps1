# 《Kane & Lynch: Dead Men》中文補丁 安裝／移除引擎（不需要 Python）
# 用法：klpatch.ps1 -Mode install | remove | verify  [-Game "遊戲資料夾"]
# 原理：場景 zip 只在檔尾追加重建後的條目與新中央目錄，原始位元組不動；移除＝截回原長度並核對 SHA-256。
# 片頭影片（manifest 的 files）是整檔替換：核對原檔 SHA-256 → 原檔改名 .orig → 複製新檔；移除＝刪新檔、.orig 改回來。
param([ValidateSet('install', 'remove', 'verify')][string]$Mode = 'install', [string]$Game = '')
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Data = Join-Path $here 'data'
$M = Get-Content (Join-Path $Data 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$Files = @(); if ($M.PSObject.Properties['files']) { $Files = @($M.files) }

Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.IO;
using System.IO.Compression;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
namespace KL1 {
public static class Engine {
    static readonly uint[] T = MakeTable();
    static uint[] MakeTable() { uint[] t = new uint[256]; for (uint n = 0; n < 256; n++) { uint c = n; for (int k = 0; k < 8; k++) c = ((c & 1) != 0) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1); t[n] = c; } return t; }
    public static uint Crc32(byte[] d, long len) { uint c = 0xFFFFFFFFu; for (long i = 0; i < len; i++) c = T[(c ^ d[i]) & 0xFF] ^ (c >> 8); return c ^ 0xFFFFFFFFu; }
    static void ReadFull(Stream s, byte[] b, long off, long n) { while (n > 0) { int k = s.Read(b, (int)off, (int)Math.Min(n, 1 << 24)); if (k <= 0) throw new IOException("資料提前結束"); off += k; n -= k; } }
    static void Put16(byte[] b, int p, int v) { b[p] = (byte)v; b[p + 1] = (byte)(v >> 8); }
    static void Put32(byte[] b, int p, uint v) { b[p] = (byte)v; b[p + 1] = (byte)(v >> 8); b[p + 2] = (byte)(v >> 16); b[p + 3] = (byte)(v >> 24); }
    public static string Sha256Prefix(string path, long len) {
        using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20))
        using (SHA256 sha = SHA256.Create()) {
            byte[] buf = new byte[1 << 22]; long left = len;
            while (left > 0) { int n = f.Read(buf, 0, (int)Math.Min(buf.Length, left)); if (n <= 0) throw new IOException("檔案比預期短：" + path); sha.TransformBlock(buf, 0, n, null, 0); left -= n; }
            sha.TransformFinalBlock(buf, 0, 0);
            return BitConverter.ToString(sha.Hash).Replace("-", "").ToLowerInvariant();
        }
    }
    // 0 = 原版；1 = 已裝過補丁（前段是原版）；-1 = 不是支援的版本
    public static int CheckOriginal(string path, long origSize, string origSha) {
        long size = new FileInfo(path).Length;
        if (size < origSize) return -1;
        if (Sha256Prefix(path, origSize) != origSha) return -1;
        return size > origSize ? 1 : 0;
    }
    public static void Truncate(string path, long size) { using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None)) f.SetLength(size); }
    class Cd { public byte[] Raw; public List<int> Pos = new List<int>(); public List<string> Names = new List<string>(); public int Count; }
    static Cd ReadCd(FileStream f, long limit) {
        int n = (int)Math.Min(limit, 70000); byte[] buf = new byte[n]; f.Seek(limit - n, SeekOrigin.Begin); ReadFull(f, buf, 0, n);
        int i = -1; for (int p = n - 22; p >= 0; p--) if (buf[p] == 0x50 && buf[p + 1] == 0x4b && buf[p + 2] == 5 && buf[p + 3] == 6) { i = p; break; }
        if (i < 0) throw new Exception("找不到 zip 目錄");
        Cd cd = new Cd(); cd.Count = BitConverter.ToUInt16(buf, i + 10);
        uint size = BitConverter.ToUInt32(buf, i + 12); uint off = BitConverter.ToUInt32(buf, i + 16);
        cd.Raw = new byte[size]; f.Seek(off, SeekOrigin.Begin); ReadFull(f, cd.Raw, 0, size);
        int q = 0;
        for (int k = 0; k < cd.Count; k++) {
            if (BitConverter.ToUInt32(cd.Raw, q) != 0x02014b50u) throw new Exception("zip 目錄損壞");
            int nl = BitConverter.ToUInt16(cd.Raw, q + 28), el = BitConverter.ToUInt16(cd.Raw, q + 30), cl = BitConverter.ToUInt16(cd.Raw, q + 32);
            cd.Pos.Add(q); cd.Names.Add(Encoding.ASCII.GetString(cd.Raw, q + 46, nl)); q += 46 + nl + el + cl;
        }
        return cd;
    }
    static byte[] ReadEntry(FileStream f, Cd cd, string name, long minCap, out long usize) {
        int k = cd.Names.IndexOf(name); if (k < 0) throw new Exception("zip 內找不到 " + name);
        int q = cd.Pos[k]; int method = BitConverter.ToUInt16(cd.Raw, q + 10);
        usize = BitConverter.ToUInt32(cd.Raw, q + 24); uint lo = BitConverter.ToUInt32(cd.Raw, q + 42);
        byte[] lh = new byte[30]; f.Seek(lo, SeekOrigin.Begin); ReadFull(f, lh, 0, 30);
        if (BitConverter.ToUInt32(lh, 0) != 0x04034b50u) throw new Exception("zip 記錄損壞：" + name);
        int nl = BitConverter.ToUInt16(lh, 26), el = BitConverter.ToUInt16(lh, 28);
        f.Seek(lo + 30 + nl + el, SeekOrigin.Begin);
        byte[] buf = new byte[Math.Max(usize, minCap)];
        if (method == 0) ReadFull(f, buf, 0, usize);
        else if (method == 8) { using (DeflateStream ds = new DeflateStream(f, CompressionMode.Decompress, true)) ReadFull(ds, buf, 0, usize); }
        else throw new Exception("不支援的壓縮方式：" + name);
        return buf;
    }
    static byte[] Gunzip(string path) { using (FileStream fs = File.OpenRead(path)) using (GZipStream gz = new GZipStream(fs, CompressionMode.Decompress)) using (MemoryStream ms = new MemoryStream()) { gz.CopyTo(ms); return ms.ToArray(); } }
    static byte[] ApplyDelta(string deltaPath, FileStream srcZip, Cd srcCd, string entry, out long len, out uint crc) {
        using (FileStream fs = File.OpenRead(deltaPath)) using (GZipStream gz = new GZipStream(fs, CompressionMode.Decompress)) using (BinaryReader br = new BinaryReader(gz)) {
            if (Encoding.ASCII.GetString(br.ReadBytes(4)) != "KL1D") throw new Exception("差異檔格式錯誤：" + deltaPath);
            br.ReadInt32();
            long srcLen = br.ReadInt64(); uint srcCrc = br.ReadUInt32(); long dstLen = br.ReadInt64(); uint dstCrc = br.ReadUInt32(); int nrec = br.ReadInt32();
            long usize; byte[] buf = ReadEntry(srcZip, srcCd, entry, dstLen, out usize);
            if (usize != srcLen || Crc32(buf, usize) != srcCrc) throw new Exception("原始資料與補丁不符：" + entry);
            for (int i = 0; i < nrec; i++) { long off = br.ReadInt64(); int n = br.ReadInt32(); ReadFull(gz, buf, off, n); }
            len = dstLen; crc = Crc32(buf, len);
            if (crc != dstCrc) throw new Exception("補丁結果校驗失敗：" + entry);
            return buf;
        }
    }
    // 在 zip（已是原版長度）尾端追加 names[i] 的新內容（deltas[i] 或 fulls[i] 二擇一），再寫新中央目錄、EOCD 與 IOI 尾巴
    public static void PatchZip(string zipPath, long origSize, string dataDir, string[] names, string[] deltas, string[] fulls) {
        bool ok = false;
        try {
            using (FileStream f = new FileStream(zipPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None, 1 << 20)) {
                Cd cd = ReadCd(f, origSize);
                long pos = origSize;
                for (int i = 0; i < names.Length; i++) {
                    byte[] data; long len; uint crc;
                    if (!string.IsNullOrEmpty(deltas[i])) data = ApplyDelta(Path.Combine(dataDir, deltas[i]), f, cd, names[i], out len, out crc);
                    else { data = Gunzip(Path.Combine(dataDir, fulls[i])); len = data.Length; crc = Crc32(data, len); }
                    int k = cd.Names.IndexOf(names[i]); if (k < 0) throw new Exception("zip 內找不到 " + names[i]);
                    int q = cd.Pos[k]; ushort time = BitConverter.ToUInt16(cd.Raw, q + 12), date = BitConverter.ToUInt16(cd.Raw, q + 14);
                    byte[] fn = Encoding.ASCII.GetBytes(names[i]); byte[] lh = new byte[30 + fn.Length];
                    Put32(lh, 0, 0x04034b50u); Put16(lh, 4, 20); Put16(lh, 6, 0); Put16(lh, 8, 8); Put16(lh, 10, time); Put16(lh, 12, date);
                    Put32(lh, 14, crc); Put32(lh, 18, 0); Put32(lh, 22, (uint)len); Put16(lh, 26, fn.Length); Put16(lh, 28, 0); Array.Copy(fn, 0, lh, 30, fn.Length);
                    f.Seek(pos, SeekOrigin.Begin); f.Write(lh, 0, lh.Length);
                    long dataStart = f.Position;
                    using (DeflateStream ds = new DeflateStream(f, CompressionLevel.Fastest, true)) ds.Write(data, 0, (int)len);
                    long csize = f.Position - dataStart;
                    f.Seek(pos + 18, SeekOrigin.Begin); f.Write(BitConverter.GetBytes((uint)csize), 0, 4);
                    Put16(cd.Raw, q + 8, 0); Put16(cd.Raw, q + 10, 8); Put32(cd.Raw, q + 16, crc); Put32(cd.Raw, q + 20, (uint)csize); Put32(cd.Raw, q + 24, (uint)len); Put32(cd.Raw, q + 42, (uint)pos);
                    Console.WriteLine("    " + names[i] + "  " + (len >> 10) + " KB");
                    pos = dataStart + csize;
                }
                f.Seek(pos, SeekOrigin.Begin);
                long cdOff = pos; f.Write(cd.Raw, 0, cd.Raw.Length);
                byte[] eocd = new byte[22]; Put32(eocd, 0, 0x06054b50u); Put16(eocd, 8, cd.Count); Put16(eocd, 10, cd.Count); Put32(eocd, 12, (uint)cd.Raw.Length); Put32(eocd, 16, (uint)cdOff);
                f.Write(eocd, 0, 22);
                byte[] tail = new byte[22]; tail[0] = (byte)'e'; tail[1] = (byte)'n'; tail[2] = (byte)'u'; tail[3] = (byte)'R'; Put32(tail, 16, (uint)cdOff);
                f.Write(tail, 0, 22);
                f.SetLength(f.Position);
            }
            ok = true;
        } finally { if (!ok) { try { Truncate(zipPath, origSize); } catch { } } }
    }
}
}
'@

function Find-Game {
    if ($Game -and (Test-Path (Join-Path $Game 'kaneandlynch.exe'))) { return $Game }
    $cands = @()
    try { $steam = (Get-ItemProperty 'HKCU:\Software\Valve\Steam' -ErrorAction Stop).SteamPath -replace '/', '\' } catch { $steam = $null }
    if ($steam) {
        $cands += Join-Path $steam 'steamapps\common\Kane and Lynch Dead Men'
        $vdf = Join-Path $steam 'steamapps\libraryfolders.vdf'
        if (Test-Path $vdf) { foreach ($m in [regex]::Matches((Get-Content $vdf -Raw), '"path"\s+"([^"]+)"')) { $cands += Join-Path ($m.Groups[1].Value -replace '\\\\', '\') 'steamapps\common\Kane and Lynch Dead Men' } }
    }
    foreach ($k in 'HKLM:\SOFTWARE\WOW6432Node\GOG.com\Games\1721096025', 'HKLM:\SOFTWARE\GOG.com\Games\1721096025') {
        try { $gp = (Get-ItemProperty $k -ErrorAction Stop).path; if ($gp) { $cands += $gp } } catch { }
    }
    foreach ($root in @("${env:ProgramFiles(x86)}\GOG Galaxy\Games", 'C:\GOG Games', 'D:\GOG Games', 'E:\GOG Games', 'C:\', 'D:\', 'E:\')) { if ($root) { $cands += Join-Path $root 'Kane and Lynch Dead Men' } }
    $found = @()
    foreach ($c in $cands) {
        if ($c -and (Test-Path (Join-Path $c 'kaneandlynch.exe'))) { $full = (Resolve-Path $c).Path.TrimEnd('\'); if ($found -notcontains $full) { $found += $full } }
    }
    if ($found.Count -eq 1) { return $found[0] }
    if ($found.Count -gt 1) {
        Write-Host '找到多個遊戲資料夾（Steam／GOG 版都可以）：'
        for ($i = 0; $i -lt $found.Count; $i++) { Write-Host ("  [{0}] {1}" -f ($i + 1), $found[$i]) }
        $pick = Read-Host '要安裝到哪一個？輸入編號'
        if ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $found.Count) { return $found[[int]$pick - 1] }
    }
    $typed = (Read-Host '找不到遊戲資料夾，請貼上含 kaneandlynch.exe 的資料夾路徑（Steam 版或 GOG 版都可以）').Trim('"', ' ')
    if (Test-Path (Join-Path $typed 'kaneandlynch.exe')) { return $typed }
    throw '找不到遊戲資料夾'
}

# 一個封包可能有多種原版（Steam 版、GOG 版…）：manifest 的 orig_size／orig_sha256 是主要版本，alts[] 是其他版本（可各自帶 entries）。
# 回傳符合這個檔案的版本（hashtable：label／orig_size／orig_sha256／entries），都不符合回傳 $null。
function Resolve-Orig($z, $p) {
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    $vars = @(@{ label = 'steam'; orig_size = [long]$z.orig_size; orig_sha256 = $z.orig_sha256; entries = $z.entries })
    if ($z.PSObject.Properties['alts']) {
        foreach ($a in $z.alts) {
            $ent = $z.entries; if ($a.PSObject.Properties['entries']) { $ent = $a.entries }
            $vars += @{ label = $a.label; orig_size = [long]$a.orig_size; orig_sha256 = $a.orig_sha256; entries = $ent }
        }
    }
    foreach ($v in $vars) { if ([KL1.Engine]::CheckOriginal($p, [long]$v.orig_size, $v.orig_sha256) -ge 0) { return $v } }
    return $null
}

$game = Find-Game
Write-Host "《Kane & Lynch: Dead Men》中文補丁 v$($M.version)　遊戲資料夾：$game"
if (Get-Process kaneandlynch -ErrorAction SilentlyContinue) { throw '遊戲還在執行，請先關閉。' }
$state = Join-Path $game 'KL1_zh_installed.json'
$sw = [Diagnostics.Stopwatch]::StartNew(); $ok = 0

if ($Mode -eq 'install') {
    Write-Host '檢查遊戲檔案…'
    $variants = @{}
    foreach ($z in $M.zips) {
        $p = Join-Path $game $z.rel
        if (-not (Test-Path -LiteralPath $p)) { throw "找不到 $($z.rel)" }
        $v = Resolve-Orig $z $p
        if (-not $v) { throw "檔案與支援的版本（Steam／GOG）不符：$($z.rel)（Steam 版請先「驗證遊戲檔案完整性」，GOG 版請用 Galaxy「驗證／修復」，再重新安裝補丁）" }
        $variants[$z.rel] = $v
    }
    foreach ($f in $Files) {
        $p = Join-Path $game $f.rel; $bk = "$p.orig"
        $okBk = (Test-Path -LiteralPath $bk) -and ([KL1.Engine]::CheckOriginal($bk, [long]$f.orig_size, $f.orig_sha256) -eq 0)
        $okP = (Test-Path -LiteralPath $p) -and ([KL1.Engine]::CheckOriginal($p, [long]$f.orig_size, $f.orig_sha256) -eq 0)
        $okNew = (Test-Path -LiteralPath $p) -and ([KL1.Engine]::CheckOriginal($p, [long]$f.new_size, $f.new_sha256) -eq 0)
        if (-not ($okBk -or $okP -or $okNew)) { throw "檔案與支援的版本（Steam／GOG）不符：$($f.rel)（Steam 版請先「驗證遊戲檔案完整性」，GOG 版請用 Galaxy「驗證／修復」，再重新安裝補丁）" }
    }
    foreach ($z in $M.zips) {
        $p = Join-Path $game $z.rel
        $v = $variants[$z.rel]
        if ((Get-Item -LiteralPath $p).Length -gt $v.orig_size) { [KL1.Engine]::Truncate($p, [long]$v.orig_size) }
        $tag = ''; if ($v.label -ne 'steam') { $tag = "（$($v.label) 版原檔）" }
        Write-Host "  安裝 $($z.rel)$tag"
        $names = @($v.entries | ForEach-Object { $_.name }); $deltas = @($v.entries | ForEach-Object { if ($_.delta) { $_.delta } else { '' } }); $fulls = @($v.entries | ForEach-Object { if ($_.full) { $_.full } else { '' } })
        [KL1.Engine]::PatchZip($p, [long]$v.orig_size, $Data, [string[]]$names, [string[]]$deltas, [string[]]$fulls)
        $ok++
    }
    foreach ($f in $Files) {
        $p = Join-Path $game $f.rel; $bk = "$p.orig"
        Write-Host "  安裝 $($f.rel)（整檔替換，原檔保留為 $(Split-Path -Leaf $bk)）"
        $okBk = (Test-Path -LiteralPath $bk) -and ([KL1.Engine]::CheckOriginal($bk, [long]$f.orig_size, $f.orig_sha256) -eq 0)
        if (-not $okBk) {
            if ((Test-Path -LiteralPath $p) -and ([KL1.Engine]::CheckOriginal($p, [long]$f.orig_size, $f.orig_sha256) -eq 0)) { Move-Item -LiteralPath $p -Destination $bk -Force }
            else { Write-Host '    （沒有原檔可備份；移除補丁時請用 Steam「驗證遊戲檔案完整性」或 GOG Galaxy「驗證／修復」還原這個檔）' }
        }
        Copy-Item -LiteralPath (Join-Path $Data $f.file) -Destination $p -Force
        if ([KL1.Engine]::CheckOriginal($p, [long]$f.new_size, $f.new_sha256) -ne 0) { throw "複製後校驗失敗：$($f.rel)" }
        $ok++
    }
    $isGog = Test-Path (Join-Path $game 'goggame-1721096025.info')
    @{ version = $M.version; lang = $M.lang; platform = $(if ($isGog) { 'gog' } else { 'steam' }); installed = (Get-Date).ToString('s') } | ConvertTo-Json | Set-Content -LiteralPath $state -Encoding UTF8
    Write-Host "`n完成：$ok 個檔案已安裝（$([int]$sw.Elapsed.TotalSeconds) 秒）。"
    if ($isGog) { Write-Host '提醒：GOG 版不需要 Games for Windows LIVE；' }
    else { Write-Host '提醒：第一次玩要裝遊戲內附的 Games for Windows LIVE（XLiveRedist\XLiveRedist01.02.0241.00.msi）；' }
    Write-Host '      若出現 Direct3D 錯誤，請在 %LOCALAPPDATA%\kaneandlynch\main.ini 加一行 Window 1（視窗模式）。'
} elseif ($Mode -eq 'remove') {
    foreach ($z in $M.zips) {
        $p = Join-Path $game $z.rel
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $v = Resolve-Orig $z $p
        if (-not $v) { Write-Host "  $($z.rel)：不是支援的版本，略過（請用 Steam 驗證完整性或 GOG Galaxy 驗證／修復）"; continue }
        if ((Get-Item -LiteralPath $p).Length -gt $v.orig_size) {
            [KL1.Engine]::Truncate($p, [long]$v.orig_size)
            $h = [KL1.Engine]::Sha256Prefix($p, [long]$v.orig_size)
            Write-Host ("  已還原 {0}{1}" -f $z.rel, $(if ($h -eq $v.orig_sha256) { '' } else { '（雜湊不符，請用 Steam 驗證完整性或 GOG Galaxy 驗證／修復）' }))
            $ok++
        }
    }
    foreach ($f in $Files) {
        $p = Join-Path $game $f.rel; $bk = "$p.orig"
        if (Test-Path -LiteralPath $bk) {
            if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
            Move-Item -LiteralPath $bk -Destination $p -Force
            $st = [KL1.Engine]::CheckOriginal($p, [long]$f.orig_size, $f.orig_sha256)
            Write-Host ("  已還原 {0}{1}" -f $f.rel, $(if ($st -eq 0) { '' } else { '（雜湊不符，請用 Steam 驗證完整性或 GOG Galaxy 驗證／修復）' }))
            $ok++
        } elseif ((Test-Path -LiteralPath $p) -and ([KL1.Engine]::CheckOriginal($p, [long]$f.orig_size, $f.orig_sha256) -ne 0)) {
            Write-Host "  $($f.rel)：找不到原檔備份，請用 Steam「驗證遊戲檔案完整性」或 GOG Galaxy「驗證／修復」還原"
        }
    }
    Remove-Item -LiteralPath $state -ErrorAction SilentlyContinue
    Write-Host "`n完成：已還原 $ok 個檔案。"
} else {
    foreach ($z in $M.zips) {
        $p = Join-Path $game $z.rel
        $v = Resolve-Orig $z $p; $st = -1; $tag = ''
        if ($v) { $st = [KL1.Engine]::CheckOriginal($p, [long]$v.orig_size, $v.orig_sha256); if ($v.label -ne 'steam') { $tag = "（$($v.label) 版）" } }
        Write-Host ("  {0}: {1}{2}" -f $z.rel, @{ 0 = '原版'; 1 = '已安裝補丁'; -1 = '不是原版' }[[int]$st], $tag)
    }
    foreach ($f in $Files) {
        $p = Join-Path $game $f.rel; $st = -1
        if (Test-Path -LiteralPath $p) {
            if ([KL1.Engine]::CheckOriginal($p, [long]$f.orig_size, $f.orig_sha256) -eq 0) { $st = 0 }
            elseif ([KL1.Engine]::CheckOriginal($p, [long]$f.new_size, $f.new_sha256) -eq 0) { $st = 1 }
        }
        Write-Host ("  {0}: {1}" -f $f.rel, @{ 0 = '原版'; 1 = '已安裝補丁'; -1 = '不是原版' }[[int]$st])
    }
}
