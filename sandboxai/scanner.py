"""
Core scanning logic for ThreatScope
Integrates with VirusTotal and Hybrid Analysis APIs
"""

import requests
import time
import hashlib
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, Set
from datetime import datetime


@dataclass
class VTResult:
    """VirusTotal scan results"""
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total: int = 0
    detected_by: list = None
    sha256: Optional[str] = None
    file_type: Optional[str] = None
    last_analysis: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class HAResult:
    """Hybrid Analysis scan results"""
    verdict: Optional[str] = None
    threat_score: Optional[int] = None
    threat_level: Optional[int] = None
    malware_family: Optional[str] = None
    tags: list = None
    sha256: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ScanResult:
    """Complete scan result"""
    target: str
    scan_type: str  # 'url', 'hash', 'file'
    timestamp: str
    verdict: str  # 'safe', 'warning', 'danger'
    vt: Optional[VTResult] = None
    ha: Optional[HAResult] = None

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "type": self.scan_type,
            "timestamp": self.timestamp,
            "verdict": self.verdict,
            "vt": self.vt.to_dict() if self.vt else None,
            "ha": self.ha.to_dict() if self.ha else None,
        }


class ThreatScopeScanner:
    """Main scanner class"""

    VT_API_URL = "https://www.virustotal.com/api/v3"
    HA_API_URL = "https://www.hybrid-analysis.com/api/v2"

    def __init__(self, vt_key: str = None, ha_key: str = None, timeout: int = 30):
        self.vt_key = vt_key
        self.ha_key = ha_key
        self.timeout = timeout
        self.session = requests.Session()

    def scan(self, target: str, engines: Set[str]) -> ScanResult:
        """Main scan method"""
        # Determine scan type
        scan_type = self._determine_type(target)

        result = ScanResult(
            target=target,
            scan_type=scan_type,
            timestamp=datetime.now().isoformat(),
            verdict="pending",
            vt=VTResult(),
            ha=HAResult()
        )

        # Run scans in parallel concept (sequential here)
        if "vt" in engines and self.vt_key:
            self._scan_virustotal(result, target, scan_type)

        if "ha" in engines and self.ha_key:
            self._scan_hybrid_analysis(result, target, scan_type)

        # Finalize verdict
        self._determine_verdict(result)

        return result

    def _determine_type(self, target: str) -> str:
        """Determine if target is URL, hash, or file"""
        # Check if file exists
        if Path(target).exists() and Path(target).is_file():
            return "file"

        # Check if hash (MD5, SHA-1, SHA-256)
        target_lower = target.lower()
        if len(target) in [32, 40, 64] and all(c in "0123456789abcdef" for c in target_lower):
            return "hash"

        # Otherwise URL/domain/IP
        return "url"

    def _scan_virustotal(self, result: ScanResult, target: str, scan_type: str) -> None:
        """Scan using VirusTotal API"""
        try:
            headers = {"x-apikey": self.vt_key}

            if scan_type == "hash":
                print(f"  🔵 VirusTotal: Looking up hash...")
                resp = self.session.get(
                    f"{self.VT_API_URL}/files/{target}",
                    headers=headers,
                    timeout=self.timeout
                )
                if resp.status_code == 404:
                    result.vt.error = "Hash not found in VirusTotal"
                    return
                resp.raise_for_status()
                result.vt = self._parse_vt_file_report(resp.json())

            elif scan_type == "url":
                print(f"  🔵 VirusTotal: Submitting URL...")
                # Submit URL
                submit_data = {"url": target}
                submit_resp = self.session.post(
                    f"{self.VT_API_URL}/urls",
                    data=submit_data,
                    headers=headers,
                    timeout=self.timeout
                )
                submit_resp.raise_for_status()
                analysis_id = submit_resp.json().get("data", {}).get("id")

                if not analysis_id:
                    raise ValueError("No analysis ID returned from VirusTotal")

                # Poll for results
                print(f"  🔵 VirusTotal: Waiting for analysis...")
                for i in range(8):
                    time.sleep(3)
                    poll_resp = self.session.get(
                        f"{self.VT_API_URL}/analyses/{analysis_id}",
                        headers=headers,
                        timeout=self.timeout
                    )
                    if poll_resp.status_code == 200:
                        poll_data = poll_resp.json()
                        if poll_data.get("data", {}).get("attributes", {}).get("status") == "completed":
                            result.vt = self._parse_vt_analysis(poll_data)
                            return

                # Fallback: try URL lookup
                url_id = self._encode_url(target)
                fallback_resp = self.session.get(
                    f"{self.VT_API_URL}/urls/{url_id}",
                    headers=headers,
                    timeout=self.timeout
                )
                if fallback_resp.status_code == 200:
                    result.vt = self._parse_vt_file_report(fallback_resp.json())

            elif scan_type == "file":
                print(f"  🔵 VirusTotal: Uploading file...")
                with open(target, "rb") as f:
                    files = {"file": f}
                    upload_resp = self.session.post(
                        f"{self.VT_API_URL}/files",
                        files=files,
                        headers=headers,
                        timeout=120
                    )
                upload_resp.raise_for_status()
                analysis_id = upload_resp.json().get("data", {}).get("id")

                if not analysis_id:
                    raise ValueError("No analysis ID from file upload")

                # Poll for results
                print(f"  🔵 VirusTotal: Scanning file...")
                for i in range(12):
                    time.sleep(5)
                    poll_resp = self.session.get(
                        f"{self.VT_API_URL}/analyses/{analysis_id}",
                        headers=headers,
                        timeout=self.timeout
                    )
                    if poll_resp.status_code == 200:
                        poll_data = poll_resp.json()
                        if poll_data.get("data", {}).get("attributes", {}).get("status") == "completed":
                            result.vt = self._parse_vt_analysis(poll_data)
                            return

        except Exception as e:
            result.vt.error = f"VT Error: {str(e)}"

    def _scan_hybrid_analysis(self, result: ScanResult, target: str, scan_type: str) -> None:
        """Scan using Hybrid Analysis API"""
        try:
            headers = {
                "api-key": self.ha_key,
                "User-Agent": "Falcon Sandbox",
                "Accept": "application/json"
            }

            if scan_type == "hash":
                print(f"  🟠 Hybrid Analysis: Querying hash...")
                resp = self.session.get(
                    f"{self.HA_API_URL}/overview/{target}",
                    headers=headers,
                    timeout=self.timeout
                )
                if resp.status_code == 404:
                    result.ha.error = "Hash not found in Hybrid Analysis"
                    return
                resp.raise_for_status()
                result.ha = self._parse_ha_report(resp.json())

            elif scan_type == "url":
                print(f"  🟠 Hybrid Analysis: Searching URL...")
                search_resp = self.session.post(
                    f"{self.HA_API_URL}/search/terms",
                    headers=headers,
                    data={"url": target},
                    timeout=self.timeout
                )
                if search_resp.status_code == 200 and search_resp.json().get("result"):
                    result.ha = self._parse_ha_result(search_resp.json()["result"][0])

            elif scan_type == "file":
                print(f"  🟠 Hybrid Analysis: Uploading file...")
                with open(target, "rb") as f:
                    files = {"file": f}
                    data = {"environment_id": "110"}
                    upload_resp = self.session.post(
                        f"{self.HA_API_URL}/submit/file",
                        files=files,
                        data=data,
                        headers=headers,
                        timeout=120
                    )
                upload_resp.raise_for_status()
                job_id = upload_resp.json().get("job_id") or upload_resp.json().get("sha256")

                if job_id:
                    print(f"  🟠 Hybrid Analysis: Sandbox running...")
                    for i in range(10):
                        time.sleep(8)
                        state_resp = self.session.get(
                            f"{self.HA_API_URL}/report/{job_id}/state",
                            headers=headers,
                            timeout=self.timeout
                        )
                        if state_resp.status_code == 200:
                            state_data = state_resp.json()
                            if state_data.get("state") == "SUCCESS":
                                summary_resp = self.session.get(
                                    f"{self.HA_API_URL}/report/{job_id}/summary",
                                    headers=headers,
                                    timeout=self.timeout
                                )
                                if summary_resp.status_code == 200:
                                    result.ha = self._parse_ha_report(summary_resp.json())
                                return

        except Exception as e:
            result.ha.error = f"HA Error: {str(e)}"

    def _parse_vt_file_report(self, data: Dict) -> VTResult:
        """Parse VirusTotal file report response"""
        attrs = data.get("data", {}).get("attributes", {})
        if not attrs:
            return VTResult(error="Invalid response from VirusTotal")

        stats = attrs.get("last_analysis_stats", {})
        engines = attrs.get("last_analysis_results", {})
        detected_by = [
            k for k, v in engines.items()
            if v.get("category") == "malicious"
        ][:5]

        return VTResult(
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total=sum(stats.values()),
            detected_by=detected_by,
            sha256=attrs.get("sha256"),
            file_type=attrs.get("meaningful_name") or attrs.get("type_description"),
            last_analysis=attrs.get("last_analysis_date")
        )

    def _parse_vt_analysis(self, data: Dict) -> VTResult:
        """Parse VirusTotal analysis response"""
        attrs = data.get("data", {}).get("attributes", {})
        if not attrs:
            return VTResult(error="Invalid analysis response")

        stats = attrs.get("stats", {})
        engines = attrs.get("results", {})
        detected_by = [
            k for k, v in engines.items()
            if v.get("category") == "malicious"
        ][:5]

        return VTResult(
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total=sum(stats.values()),
            detected_by=detected_by
        )

    def _parse_ha_report(self, data: Dict) -> HAResult:
        """Parse Hybrid Analysis report"""
        return HAResult(
            verdict=data.get("verdict"),
            threat_score=data.get("threat_score"),
            threat_level=data.get("threat_level"),
            malware_family=data.get("vx_family"),
            tags=data.get("tags", []),
            sha256=data.get("sha256")
        )

    def _parse_ha_result(self, data: Dict) -> HAResult:
        """Parse Hybrid Analysis search result"""
        return HAResult(
            verdict=data.get("verdict"),
            threat_score=data.get("threat_score"),
            malware_family=data.get("vx_family"),
            tags=data.get("tags", []),
            sha256=data.get("sha256")
        )

    def _determine_verdict(self, result: ScanResult) -> None:
        """Determine overall verdict from results"""
        danger = False
        warning = False

        if result.vt and not result.vt.error:
            if result.vt.malicious > 3:
                danger = True
            elif result.vt.malicious > 0 or result.vt.suspicious > 0:
                warning = True

        if result.ha and not result.ha.error:
            if result.ha.verdict in ["malicious", "suspicious"]:
                if result.ha.threat_level and result.ha.threat_level >= 2:
                    danger = True
                elif result.ha.verdict == "malicious":
                    danger = True
                else:
                    warning = True

        result.verdict = "danger" if danger else "warning" if warning else "safe"

    @staticmethod
    def _encode_url(url: str) -> str:
        """Encode URL to base64 format for VT API"""
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")