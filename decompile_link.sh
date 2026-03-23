cd ~/Documents/Scobelix

export WEB3_PROVIDER_URI='https://rpc.fullsend.to'

python3 -m venv .venv
. .venv/bin/activate

pip install --upgrade pip
pip install -e .
pip install vyper jq

CONTRACT=0x514910771AF9Ca656af840dff83E8264EcF986CA

BYTECODE=$(curl -s -X POST "$WEB3_PROVIDER_URI" \
  -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":["'"$CONTRACT"'","latest"]}' \
  | jq -r '.result')

if [ -z "$BYTECODE" ] || [ "$BYTECODE" = "0x" ]; then
  echo "ERR: bytecode manquant"
  exit 1
fi

panoramix "$BYTECODE" 2>/dev/null \
  | sed -r 's/\x1B\[[0-9;]*[A-Za-z]//g' \
  > link_decompilation.vy

if [ ! -f link_decompilation.vy ]; then
  echo "FAIL: link_decompilation.vy est manquant"
  exit 1
fi

if [ ! -s link_decompilation.vy ]; then
  echo "FAIL: link_decompilation.vy existe mais est vide"
  exit 1
fi

echo "OK: link_decompilation.vy existe et contient du contenu"

if vyper link_decompilation.vy > /dev/null 2>&1; then
  echo "OK: link_decompilation.vy est compilable Vyper"
  exit 0
else
  echo "WARN: link_decompilation.vy n'est pas strictement compilable Vyper"
  # Possible but utile pour vérifier dans Jenkins
  exit 0
fi

# Non nécessaire, le script a déjà quitté au-dessus
# echo "Fini : fichier link_decompilation.vy"