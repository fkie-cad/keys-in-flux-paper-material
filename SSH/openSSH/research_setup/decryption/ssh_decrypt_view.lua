-- ssh_decrypt_view.lua
-- Simple post-dissector that surfaces decrypted SSH payload bytes
-- (relies on the builtin ssh dissector to have already decrypted data).
--
-- Install: place in your Wireshark plugins folder (see README below).
-- When Wireshark has decrypted packets, this will add a subtree:
--   "SSH Decrypted Payload" and a field ssh.dec_payload with the raw bytes.

local p_sshdec = Proto("sshdec", "SSH Decrypted Payload Viewer")

-- define a bytes field for the decrypted payload
local f_dec_payload = ProtoField.bytes("ssh.dec_payload", "Decrypted SSH payload")

p_sshdec.fields = { f_dec_payload }

-- reference the existing ssh.payload field exported by the SSH dissector
-- If the built-in ssh dissector decrypted payload, it exposes the field "ssh.payload".
-- See Wireshark display filter reference for the SSH dissector fields.
local fh_ssh_payload = Field.new("ssh.payload")

function p_sshdec.dissector(buffer, pinfo, tree)
  -- get current packet's ssh.payload value (if the ssh dissector produced it)
  local payload_field = fh_ssh_payload()
  if not payload_field then
    -- nothing decrypted for this packet
    return
  end

  -- payload_field is a FieldInfo object; use its range to get a TvbRange
  local rng = payload_field.range
  if not rng then
    return
  end

  -- add a subtree with the decrypted payload
  local subtree = tree:add(p_sshdec, "SSH Decrypted Payload")
  subtree:add(f_dec_payload, rng:tvb()) -- add raw bytes

  -- optionally set a column (uncomment to show short hex in Info col)
  -- local short = tostring(rng:bytes():tohex():sub(1,64))
  -- pinfo.cols.info:append(" [ssh-decrypted:" .. short .. "...]")
end

-- register this as a postdissector so it runs after normal dissection
register_postdissector(p_sshdec)
