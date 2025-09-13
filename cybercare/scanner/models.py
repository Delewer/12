from django.db import models
from django.utils import timezone

class Target(models.Model):
    input_value = models.CharField(max_length=255, unique=False, help_text="Domeniu sau IP")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.input_value

class Scan(models.Model):
    STATUS = [
        ("queued", "Queued"),
        ("running", "Running"),
        ("done", "Done"),
        ("error", "Error"),
    ]
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name="scans")
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS, default="queued")
    score = models.IntegerField(null=True, blank=True)  # 0-100
    severity = models.CharField(max_length=10, null=True, blank=True)  # green/yellow/red

    # Stocăm rezultate brute ca JSON simplu
    ports = models.JSONField(default=dict)             # {open_ports: [...], services:[...]}
    tls = models.JSONField(default=dict)               # {valid:bool, days_left:int, min_version:str, hsts:bool}
    headers = models.JSONField(default=dict)           # {https:bool, csp:bool/xfo:bool/... raw_headers:{}}
    email_auth = models.JSONField(default=dict)        # {spf:bool, dkim:"ok/partial/missing", dmarc:bool}
    cves = models.JSONField(default=dict)              # {product:"Apache 2.4.41", items:[{cve_id, severity, url}]}
    summary = models.TextField(blank=True, default="") # Text raport

    def __str__(self):
        return f"Scan {self.id} for {self.target}"
