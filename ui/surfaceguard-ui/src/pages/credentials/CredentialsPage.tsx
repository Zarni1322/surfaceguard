import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { KeyRound, Plus, Trash2, CheckCircle, XCircle } from "lucide-react";
import { listCredentialProfiles, createCredentialProfile, deleteCredentialProfile, validateCredentials } from "@/api/client";
import type { CredentialProfile, ValidationResult } from "@/types";
import { toast } from "sonner";
import PageHeader from "@/components/PageHeader";
import PageContainer, { colSpan } from "@/components/PageContainer";
import EmptyState from "@/components/EmptyState";

export default function CredentialsPage() {
  const [profiles, setProfiles] = useState<CredentialProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [validating, setValidating] = useState<number | null>(null);
  const [vr, setVr] = useState<Record<number, ValidationResult>>({});
  const [form, setForm] = useState({ name: "", protocol: "ssh", host: "", port: 22, username: "", auth_method: "password", password: "", private_key: "", passphrase: "", community: "" });

  useEffect(() => { loadProfiles(); }, []);

  async function loadProfiles() {
    try { setProfiles(await listCredentialProfiles()); } catch { toast.error("Failed to load"); } finally { setLoading(false); }
  }

  async function handleCreate() {
    try {
      const p: any = { name: form.name, protocol: form.protocol, host: form.host, port: form.port || (form.protocol === "ssh" ? 22 : form.protocol === "snmp" ? 161 : 5986), username: form.username, auth_method: form.auth_method };
      if (form.protocol === "ssh" && form.auth_method === "password") p.password = form.password;
      else if (form.protocol === "ssh" && form.auth_method?.startsWith("key")) { p.private_key = form.private_key; if (form.auth_method === "key+passphrase") p.passphrase = form.passphrase; }
      else if (form.protocol === "winrm") p.password = form.password;
      else if (form.protocol === "snmp" && form.auth_method === "community") p.community = form.community;
      await createCredentialProfile(p);
      toast.success("Created");
      setShowForm(false);
      setForm({ name: "", protocol: "ssh", host: "", port: 22, username: "", auth_method: "password", password: "", private_key: "", passphrase: "", community: "" });
      loadProfiles();
    } catch { toast.error("Create failed"); }
  }

  async function handleDelete(id: number) { try { await deleteCredentialProfile(id); toast.success("Deleted"); loadProfiles(); } catch { toast.error("Delete failed"); } }

  async function handleValidate(id: number) {
    setValidating(id);
    try { const r = await validateCredentials(id); setVr((p) => ({ ...p, [id]: r })); toast.success(r.status === "SUCCESS" ? "OK" : `Validation: ${r.status}`); } catch { toast.error("Validation failed"); } finally { setValidating(null); }
  }

  return (
    <PageContainer>
      <div className={colSpan(12)}>
        <PageHeader title="Credential Profiles" description="Manage reusable authentication templates"
          actions={<Button onClick={() => setShowForm(!showForm)} size="sm" className="bg-[#3B82F6]"><Plus className="h-4 w-4 mr-1" />New Profile</Button>} />
      </div>

      {showForm && (
        <div className={colSpan(12)}>
          <Card className="border-[#1E293B] bg-[#1E293B]">
            <CardHeader className="pb-3"><CardTitle className="text-base text-[#F8FAFC]">New Profile</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div><label className="block text-xs text-[#94A3B8] mb-1">Name</label><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Linux Prod" className="bg-[#0B1220] border-[#1E293B] text-[#F8FAFC] text-sm" /></div>
                <div><label className="block text-xs text-[#94A3B8] mb-1">Protocol</label><select value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value })} className="w-full bg-[#0B1220] border border-[#1E293B] rounded-md p-2 text-[#F8FAFC] text-sm">{["ssh","winrm","snmp"].map(v => <option key={v} value={v}>{v.toUpperCase()}</option>)}</select></div>
                <div><label className="block text-xs text-[#94A3B8] mb-1">Host</label><Input value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="10.0.0.1" className="bg-[#0B1220] border-[#1E293B] text-[#F8FAFC] text-sm" /></div>
                <div><label className="block text-xs text-[#94A3B8] mb-1">Port</label><Input type="number" value={form.port} onChange={(e) => setForm({ ...form, port: parseInt(e.target.value) || 0 })} className="bg-[#0B1220] border-[#1E293B] text-[#F8FAFC] text-sm" /></div>
                <div><label className="block text-xs text-[#94A3B8] mb-1">Username</label><Input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} className="bg-[#0B1220] border-[#1E293B] text-[#F8FAFC] text-sm" /></div>
                <div><label className="block text-xs text-[#94A3B8] mb-1">Auth</label><select value={form.auth_method} onChange={(e) => setForm({ ...form, auth_method: e.target.value })} className="w-full bg-[#0B1220] border border-[#1E293B] rounded-md p-2 text-[#F8FAFC] text-sm">{form.protocol === "ssh" ? <><option value="password">Password</option><option value="key">Key</option><option value="key+passphrase">Key+Passphrase</option></> : form.protocol === "snmp" ? <><option value="community">Community</option><option value="snmpv3">SNMPv3</option></> : <option value="password">Password</option>}</select></div>
                {(form.auth_method === "password" || form.protocol === "winrm") && <div><label className="block text-xs text-[#94A3B8] mb-1">Secret</label><Input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} className="bg-[#0B1220] border-[#1E293B] text-[#F8FAFC] text-sm" /></div>}
                {form.auth_method?.startsWith("key") && <div className="md:col-span-2"><label className="block text-xs text-[#94A3B8] mb-1">Private Key</label><textarea value={form.private_key} onChange={(e) => setForm({ ...form, private_key: e.target.value })} rows={3} className="w-full bg-[#0B1220] border border-[#1E293B] rounded-md p-2 text-[#F8FAFC] font-mono text-xs" /></div>}
                {form.auth_method === "key+passphrase" && <div><label className="block text-xs text-[#94A3B8] mb-1">Passphrase</label><Input type="password" value={form.passphrase} onChange={(e) => setForm({ ...form, passphrase: e.target.value })} className="bg-[#0B1220] border-[#1E293B] text-[#F8FAFC] text-sm" /></div>}
                {form.protocol === "snmp" && form.auth_method === "community" && <div><label className="block text-xs text-[#94A3B8] mb-1">Community</label><Input value={form.community} onChange={(e) => setForm({ ...form, community: e.target.value })} className="bg-[#0B1220] border-[#1E293B] text-[#F8FAFC] text-sm" /></div>}
              </div>
              <Button onClick={handleCreate} size="sm" className="bg-[#3B82F6]"><KeyRound className="h-4 w-4 mr-1" />Save</Button>
            </CardContent>
          </Card>
        </div>
      )}

      {loading ? <div className={colSpan(12)}><p className="text-[#94A3B8] text-sm">Loading...</p></div>
        : profiles.length === 0 ? <div className={colSpan(12)}><Card className="border-[#1E293B] bg-[#1E293B]"><CardContent><EmptyState icon={KeyRound} title="No credential profiles" description="Create a profile to start authenticated assessments" /></CardContent></Card></div>
        : <div className={colSpan(12)}><div className="space-y-2">{profiles.map((p) => (
            <Card key={p.id} className="border-[#1E293B] bg-[#1E293B]">
              <CardContent className="p-3"><div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-3 min-w-0">
                  <div className={`p-1.5 rounded-lg shrink-0 ${p.protocol === "ssh" ? "bg-green-500/10" : p.protocol === "winrm" ? "bg-blue-500/10" : "bg-yellow-500/10"}`}>
                    <KeyRound className={`h-4 w-4 ${p.protocol === "ssh" ? "text-green-400" : p.protocol === "winrm" ? "text-blue-400" : "text-yellow-400"}`} />
                  </div>
                  <div className="min-w-0">
                    <h3 className="font-medium text-sm text-[#F8FAFC]">{p.name}</h3>
                    <p className="text-xs text-[#94A3B8]">{p.protocol.toUpperCase()} · {p.host}:{p.port} · {p.username}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <Button variant="outline" size="sm" onClick={() => handleValidate(p.id)} disabled={validating === p.id} className="border-[#1E293B] text-[#94A3B8] h-7 text-xs">{validating === p.id ? "..." : "Test"}</Button>
                  <Button variant="ghost" size="sm" onClick={() => handleDelete(p.id)} className="text-red-400 h-7 w-7 p-0"><Trash2 className="h-3.5 w-3.5" /></Button>
                </div>
              </div>
              {vr[p.id] && (
                <div className="mt-2 pt-2 border-t border-[#0B1220]">
                  <div className="flex items-center gap-1.5 mb-1">
                    {vr[p.id].status === "SUCCESS" ? <CheckCircle className="h-3.5 w-3.5 text-green-400" /> : <XCircle className="h-3.5 w-3.5 text-red-400" />}
                    <span className={`text-xs font-medium ${vr[p.id].status === "SUCCESS" ? "text-green-400" : "text-red-400"}`}>{vr[p.id].status}</span>
                  </div>
                  {vr[p.id].checks.map((c, i) => (
                    <div key={i} className="flex items-center gap-1.5 text-xs ml-4">
                      {c.status === "pass" ? <CheckCircle className="h-3 w-3 text-green-400" /> : <XCircle className="h-3 w-3 text-red-400" />}
                      <span className="text-[#94A3B8]">{c.name}{c.message && <span className="text-[#64748B]"> — {c.message}</span>}</span>
                    </div>
                  ))}
                </div>
              )}
              </CardContent>
            </Card>
          ))}</div></div>}
    </PageContainer>
  );
}
