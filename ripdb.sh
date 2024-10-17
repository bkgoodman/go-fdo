DATA=(device_info           owner_keys            sessions incomplete_vouchers   owner_vouchers        to0_sessions key_exchanges         replacement_vouchers  to1_sessions mfg_keys              rv_blobs              to2_sessions mfg_vouchers          secrets)

for i in ${DATA[@]}; do
  echo -n $i ":  "
  sqlite3 test.db "select count(*) from $i;"
done
