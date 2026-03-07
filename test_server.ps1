$key = [byte[]]@(0xdd,0x89,0x35,0xfa,0x10,0xd1,0x33,0x0a,0xad,0x0b,0x12,0x55,0x52,0x1c,0x10,0x27,0xee,0x3c,0x9a,0x2f,0x90,0xb8,0xac,0xf6,0x6d,0x67,0x6d,0xf2,0xef,0xe1,0x03,0x3f)
$json = '{"test":"hello"}'
$jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
$ms = New-Object System.IO.MemoryStream
$gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
$gz.Write($jsonBytes, 0, $jsonBytes.Length)
$gz.Close()
$compressed = $ms.ToArray()
$hmac = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = $key
$sig = ($hmac.ComputeHash($compressed) | ForEach-Object { $_.ToString("x2") }) -join ""
Invoke-WebRequest -Uri "http://localhost:8080/ingest/test" `
  -Method POST `
  -Headers @{ "X-API-Key" = "changeme"; "X-Signature" = $sig; "Content-Encoding" = "gzip"; "Content-Type" = "application/json" } `
  -Body $compressed
