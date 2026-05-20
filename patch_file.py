import sys

def apply_patch(file_path):
    with open(file_path, 'r') as f:
        content = f.read()

    search = """function bufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    const binary = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
    return window.btoa(binary);
}"""

    replace = """function bufferToBase64(buffer: ArrayBuffer): string {
    if (typeof Buffer !== "undefined") return Buffer.from(buffer).toString("base64");
    let binary = "";
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i += 32768) binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 32768) as unknown as number[]);
    return window.btoa(binary);
}"""

    if search in content:
        content = content.replace(search, replace)
        with open(file_path, 'w') as f:
            f.write(content)
        print("Patched successfully")
    else:
        print("Search string not found")

apply_patch('web/src/lib/crypto.ts')
