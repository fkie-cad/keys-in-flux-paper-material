-- wireshark_helper.lua
-- Place under ~/.local/lib/wireshark/plugins/ or ~/.config/wireshark/plugins/
-- Adds menu: File -> SSHKex -> Decrypt PCAP with keys
local sshkex_menu = {
    name = "SSHKex",
}

local function run_decryptor()
    -- YOU MUST change paths below to your decryptor location
    local decryptor = "/usr/local/bin/ssh_decryptor.py"
    local keysjson = "/tmp/ssh-keys/keys.json"
    local inputpcap = "/tmp/ssh-capture.pcap"
    local outpcap = "/tmp/ssh-decrypted.pcap"
    local cmd = string.format("python3 %s --pcap %s --keys %s --out %s &", decryptor, inputpcap, keysjson, outpcap)
    os.execute(cmd)
    -- Inform user
    print("SSHKex: launched decryptor, output:", outpcap)
end

-- Register menu item (Wireshark calls)
register_menu("File/SSHKex/Decrypt PCAP with keys", run_decryptor, MENU_TOOLS_UNSORTED)
