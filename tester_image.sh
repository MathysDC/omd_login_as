#!/usr/bin/env bash
# Teste omd_login_as dans l'IMAGE Odoo réelle, contre un PostgreSQL 16 jetable.
# Usage : test_module_image.sh <serie>   (ex. 16.0)
set -u
SERIE=$1
IMAGE=${2:-odoo:$SERIE}
REPO=/home/mad/Documents/Perso/OmydooSH/omd_login_as
BASE=/tmp/claude-1000/-home-mad-Documents-Perso-OmydooSH/4131aade-2096-402d-a9b1-38e3f15f2bad/scratchpad/img-$SERIE-$$
RES=omd-test-$(echo "$SERIE" | tr -d '.')
nettoyer() { docker rm -f "$RES-odoo" "$RES-pg" >/dev/null 2>&1; docker network rm "$RES-net" >/dev/null 2>&1; }
trap nettoyer EXIT
nettoyer
docker run --rm -v /tmp/claude-1000/-home-mad-Documents-Perso-OmydooSH/4131aade-2096-402d-a9b1-38e3f15f2bad/scratchpad:/s alpine sh -c "rm -rf /s/'"'$(basename "$BASE")'"'" >/dev/null 2>&1
rm -rf "$BASE"; mkdir -p "$BASE/addons/omd_login_as"
git -C "$REPO" archive "$SERIE" | tar -x -C "$BASE/addons/omd_login_as"
chmod -R a+rwX "$BASE"

docker network create "$RES-net" >/dev/null
docker run -d --name "$RES-pg" --network "$RES-net" \
  -e POSTGRES_USER=odoo -e POSTGRES_PASSWORD=odoo -e POSTGRES_DB=postgres postgres:16 >/dev/null
for _ in $(seq 1 60); do docker exec "$RES-pg" pg_isready -U odoo >/dev/null 2>&1 && break; sleep 1; done

docker run --name "$RES-odoo" --network "$RES-net" \
  -e HOST="$RES-pg" -e USER=odoo -e PASSWORD=odoo \
  -v "$BASE/addons:/mnt/extra-addons" "$IMAGE" \
  -d testdb -i omd_login_as --test-enable --test-tags omydoo --stop-after-init --log-level=info \
  > "$BASE/sortie.log" 2>&1
CODE=$?
echo "--- branche $SERIE sur $IMAGE  (sortie $CODE)"
grep -o -E "[0-9]+ failed, [0-9]+ error\\(s\\) of [0-9]+ tests" "$BASE/sortie.log" | tail -1
grep -c "Starting TestLoginAs" "$BASE/sortie.log" | sed "s/^/tests lances: /"
grep -E "FAIL: |ERROR: TestLoginAs|Traceback|invalid manifest" "$BASE/sortie.log" | head -4
if [ "$CODE" = "0" ] && grep -q "0 failed, 0 error(s)" "$BASE/sortie.log"; then echo "RESULTAT: VERT"; else echo "RESULTAT: ROUGE ($BASE/sortie.log)"; fi
