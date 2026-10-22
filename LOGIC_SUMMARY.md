# NT542 Azure Secure Storage - Logic Summary

> Historical design snapshot. For current P0 behavior and safety constraints, use `README.md` and `docs/baseline.md`; Azure remediation is now plan-only by default.

## 1. Muc tieu he thong

Project nay xay dung mot moi truong Azure private-first va mot compliance engine de giam sat drift sau khi ha tang duoc tao.

Terraform chiu trach nhiem tao baseline ban dau:

- Resource Group rieng cho moi truong automation.
- Virtual Network va cac subnet noi bo.
- Storage Account, Key Vault va Azure SQL duoc cau hinh an toan.
- Private Endpoint cho Storage, Key Vault va SQL.
- VPN Point-to-Site va Jumpbox/Management VM de admin truy cap vao mang noi bo.

Compliance engine chiu trach nhiem kiem tra sau deploy:

- Doc cau hinh thuc te tren Azure.
- So sanh voi baseline mong muon.
- Phan loai van de theo severity.
- Tu dong sua neu an toan.
- Cho phep exception co thoi han cho mot so tinh huong test.
- Nang cap thanh incident neu co dau hieu truy cap nhay cam tu nguon khong tin cay.

## 2. Kien truc private-first

Ha tang duoc thiet ke theo huong khong mo public access truc tiep cho cac tai nguyen quan trong.

Luong truy cap dung:

```text
May ca nhan cua admin
-> VPN Point-to-Site
-> VNet nt542-auto-vnet
-> Jumpbox/Management VM trong ManagementSubnet
-> Storage/Key Vault/SQL qua Private Endpoint
```

Storage, Key Vault va SQL duoc dat sau Private Endpoint. Vi vay neu may ca nhan chua vao VPN hoac DNS chua resolve ve private IP, cac request toi Key Vault/SQL co the bi chan boi network policy.

## 3. Baseline ban dau bang Terraform

Terraform tao cac thanh phan chinh:

- VNet: `nt542-auto-vnet`
- GatewaySubnet: `10.1.1.0/27`
- ManagementSubnet: `10.1.2.0/24`
- PrivateEndpointSubnet: `10.1.3.0/24`
- Storage Account: `nt542autostg08`
- Key Vault: `nt542-auto-kv-g08`
- SQL Server: `nt542-auto-sqlserver-g08`
- VPN Gateway: `nt542-auto-vpngw`
- VPN client pool: `172.16.0.0/24`
- Jumpbox VM: `nt542_auto-vm-manage`

Baseline security:

- Storage HTTPS only.
- Minimum TLS enabled.
- Public network access disabled.
- Blob versioning enabled.
- Key Vault RBAC enabled.
- Key Vault purge protection enabled.
- SQL auditing enabled.
- SQL Defender enabled.
- Private Endpoint enabled for Storage, Key Vault and SQL.

## 4. Logic truoc khi update

Ban dau engine chi co 2 label:

```text
WARNING
CRITICAL
```

WARNING dung cho cac sai lech can admin xem xet, vi du:

- Blob versioning disabled.
- Key Vault key/secret missing expiry.
- SQL Azure AD admin missing.

CRITICAL dung cho cac sai lech nguy hiem va co the auto-remediate, vi du:

- Public Network Access bi bat.
- TLS bi ha thap.
- SQL auditing bi tat.
- Key Vault RBAC bi tat.
- Private Endpoint missing.

Luong xu ly cu:

```text
Collect config
-> Evaluate drift
-> WARNING: hoi admin hoac log
-> CRITICAL: auto-remediate
```

Han che cua logic cu:

- Khong phan biet drift cau hinh voi security incident.
- Exception chua co thoi han ro rang.
- Neu admin can mo public access de test thi engine co the sua lai lien tuc.
- Neu co dau hieu truy cap that tu nguon la, engine chua co co che containment rieng.

## 5. Logic sau khi update

Sau khi update, engine co 3 label:

```text
WARNING
CRITICAL
ESCALATED_CRITICAL
```

### WARNING

Dung cho drift it khan cap.

Vi du:

- Blob versioning disabled.
- Key Vault keys missing expiry date.
- Key Vault secrets missing expiry date.
- SQL Azure AD admin missing.

Xu ly:

```text
Ghi log
Day vao report
Admin xem xet sau
Khong auto-remediate manh
```

### CRITICAL

Dung cho drift nguy hiem nhung co the sua an toan.

Vi du:

- Storage Public Network Access mismatch.
- Key Vault Public Network Access mismatch.
- SQL Public Network Access mismatch.
- SQL auditing disabled.
- SQL Defender disabled.
- TLS mismatch.

Xu ly:

```text
Phat hien drift
Kiem tra co active exception khong
Neu khong co exception -> auto-remediate
Neu co exception con han -> skip remediation va ghi log
```

### ESCALATED_CRITICAL

Dung cho tinh huong co dau hieu incident, khong chi la drift.

Vi du:

- Untrusted source IP thuc hien `GetBlob` thanh cong.
- Identity khong tin cay doc secret/key.
- SQL co successful login tu nguon khong tin cay.

Dieu kien quan trong:

```text
Khong escalate chi vi IP la.
Chi escalate khi co:
untrusted source + successful sensitive operation + protected resource
```

Xu ly:

```text
Bao incident
Revoke active exception cua resource do
Containment ngay
Ghi incident log
Yeu cau admin dieu tra hau qua
```

## 6. Exception logic

Exception duoc them de ho tro truong hop admin can test co kiem soat.

Lenh mau:

```text
/exception --resource-type storage --resource-name nt542autostg08 --issue "Public Network Access mismatch" --duration 10 --reason "Connectivity test"
```

Trong do:

- `--duration` la thoi gian exception tinh bang phut.
- Khong dung `approved_by`.
- Exception duoc luu vao `Compliance/data/exceptions.json`.

Khi CRITICAL xay ra:

```text
Neu exception con han:
  skip auto-remediation
  ghi exceptions.log

Neu exception het han:
  auto-remediate ve baseline
```

Exception khong duoc phep che incident.

## 7. Incident revoke exception va containment

Logic moi quan trong nhat:

```text
Neu ESCALATED_CRITICAL xay ra trong luc exception dang active:
  revoke exception ngay
  set status = revoked
  set duration_minutes = 0
  set expires_at = now
  chay containment
```

Vi du:

```text
Admin tao exception 10 phut de mo public access.
Admin bat public network access.
Trong thoi gian do co untrusted IP GetBlob Success.
Engine detect ESCALATED_CRITICAL.
Engine revoke exception.
Engine disable public access ngay.
Engine ghi incident log va exception log.
```

Containment command theo service:

Storage:

```text
az storage account update --public-network-access Disabled
```

Key Vault:

```text
az keyvault update --public-network-access Disabled
```

SQL:

```text
az sql server update --enable-public-network false
```

## 8. Admin command listener

Engine co listener cho admin command:

```text
/exception
/getlog
```

`/exception` dung de tao exception co thoi han.

`/getlog` dung de export log ra file trong folder logs.

Vi du:

```text
/getlog --type all --lines 100
/getlog --type compliance --lines 50
/getlog --type incident --lines 50
/getlog --type exception --lines 50
```

File export co ten theo ngay gio:

```text
export_all_YYYY-MM-DD_HH-MM-SS.log
```

## 9. Cac loai log

Engine tach log theo muc dich:

- `compliance_monitor.log`: drift, remediation, warning, critical.
- `exceptions.log`: exception created, remediation skipped, exception revoked.
- `incidents.log`: incident evidence, containment result, manual steps.

Muc tieu la de admin doc lai de hieu:

- Chuyen gi da xay ra.
- Resource nao bi anh huong.
- He thong da lam gi.
- Admin can dieu tra tiep cai gi.

## 10. Kich ban test chinh

### Test WARNING

Tat Blob Versioning:

```text
Blob versioning disabled
-> WARNING
-> log/report
```

### Test CRITICAL

Bat Storage Public Network Access:

```text
Public Network Access mismatch
-> CRITICAL
-> auto disable public access
```

### Test CRITICAL + Exception

Tao exception 1-10 phut, sau do bat public access:

```text
CRITICAL drift
-> active exception
-> skip remediation
```

Sau khi exception het han:

```text
drift van con
-> auto-remediate
```

### Test ESCALATED_CRITICAL

Tao mock signal:

```text
untrusted_source = true
operation = GetBlob
result = Success
```

Ket qua:

```text
ESCALATED_CRITICAL
-> revoke exception neu co
-> containment
-> incident log
```

## 11. Ket luan

Sau update, he thong khong chi la compliance checker don gian.

Logic hien tai tach ro:

```text
WARNING = drift nhe, can review
CRITICAL = drift nguy hiem, co the auto sua
ESCALATED_CRITICAL = dau hieu incident, can revoke exception va containment ngay
```

Terraform tao baseline private-first.

Compliance engine giu baseline do sau deploy.

Exception cho phep test co kiem soat.

Incident luon uu tien containment va dieu tra, khong bi exception che mat.
