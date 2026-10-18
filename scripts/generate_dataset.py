"""Instructor dataset generation script. Generates illustrative educational records, not operational security data."""
import csv, numpy as np
from datetime import datetime, timedelta
from pathlib import Path

rng=np.random.default_rng(20261018)
n=52000
start=np.datetime64('2024-01-01T00:00:00')
mins=rng.integers(0, 731*24*60, n)
mins.sort()
times=start+mins.astype('timedelta64[m]')
month=(times.astype('datetime64[M]').astype(int)-np.datetime64('2024-01').astype('datetime64[M]').astype(int))
hour=(mins//60)%24
weekend=((mins//(24*60))%7>=5)
tenant_id=rng.integers(1,141,n)
host_id=rng.integers(1,5501,n)
identity_id=rng.integers(1,9801,n)
tenant_latent=rng.normal(0,.28,141)
host_latent=rng.normal(0,.27,5501)
identity_latent=rng.normal(0,.22,9801)
family=rng.choice(['authentication','endpoint','network','cloud_control','email','data_access'],n,p=[.30,.22,.17,.13,.11,.07]).astype('object')
family[(month>=20)&(rng.random(n)<.035)]='saas_audit'
source={
'authentication':'identity_provider','endpoint':'edr','network':'firewall',
'cloud_control':'cloud_audit','email':'mail_gateway','data_access':'database_audit','saas_audit':'saas_monitor'}
log_source=np.array([source[f] for f in family],dtype='object')
regions=np.array(['eu_central','eu_west','us_east','us_west','ap_south','ap_east','other'],dtype='object')
site_reg=rng.choice(regions,n,p=[.25,.23,.17,.13,.11,.08,.03]).astype('object')
remote_reg=rng.choice(['domestic','neighboring','remote','unknown'],n,p=[.73,.13,.11,.03]).astype('object')
environment=rng.choice(['cloud','on_prem','hybrid'],n,p=[.40,.34,.26]).astype('object')
asset=rng.choice(['low','medium','high','critical'],n,p=[.27,.40,.25,.08]).astype('object')
priv=rng.choice(['standard','elevated','admin','service_account'],n,p=[.68,.18,.08,.06]).astype('object')
kind=rng.choice(['workstation','server','cloud_instance','mobile','network_device'],n,p=[.42,.25,.18,.10,.05]).astype('object')
os=rng.choice(['windows','linux','macos','android_ios','network_os'],n,p=[.51,.31,.09,.06,.03]).astype('object')
mfa=(rng.random(n)<(.88-.13*(priv=='service_account')-.04*(priv=='admin'))).astype(int)
new_device=(rng.random(n)<(.14+.08*(kind=='mobile')+.03*(environment=='cloud'))).astype(int)
offhours=((hour<7)|(hour>=20)).astype(int)
late=(month>=16).astype(int)
reputation=np.clip(rng.beta(1.9,4.6,n)*110+7*(remote_reg=='remote')+5*(family=='network'),0,100)
endpoint=np.clip(rng.normal(35,15,n)+13*(asset=='critical')+8*(family=='endpoint')+7*(kind=='server'),0,100)
failures=rng.negative_binomial(2,np.clip(.48-.08*(family=='authentication')-.08*(priv=='admin'),.17,.85),n)
uniqueips=np.maximum(1,rng.poisson(1.7+.15*failures+1.3*(remote_reg=='remote'),n))
successes=rng.negative_binomial(3,.34,n)
connections=rng.negative_binomial(3,np.clip(.26-.06*(family=='network'),.08,.9),n)
outbound=rng.lognormal(1.55,1.15,n)*(1+.6*(family=='data_access'))
inbound=rng.lognormal(1.65,.95,n)
unknown_port=(rng.random(n)<(.09+.1*(family=='network'))).astype(int)
geo_velocity=np.clip(rng.lognormal(4.15,1.2,n)*(1.4*(remote_reg=='remote')+.9*(remote_reg!='remote')),0,25000)
patch=np.clip(rng.gamma(2.6,27,n)+25*(kind=='server'),0,1200)
account_age=np.clip(rng.lognormal(5.45,1.03,n),1,3800)
prior=rng.negative_binomial(2,.39,n)
alert_burst=rng.negative_binomial(2,.47,n)
# Stable risk mechanism uses only features available when alert was raised, with nontrivial noise.
raw=(.64*(reputation-33)/22+.48*(endpoint-43)/18+
 .44*np.log1p(failures)+.28*np.log1p(uniqueips)+.30*np.log1p(prior)+
 .21*np.log1p(alert_burst)+.23*np.log1p(connections)+.28*np.log1p(outbound)/3+
 .53*unknown_port+.37*new_device+.34*(1-mfa)+.22*offhours+
 .33*(priv=='admin')+.21*(priv=='elevated')+.24*(asset=='critical')+
 .26*(remote_reg=='remote')+.22*(family=='data_access')+
 .21*(family=='cloud_control')+.27*(family=='saas_audit')+
 .22*(geo_velocity>900)+.22*(patch>120)+.15*late+
 tenant_latent[tenant_id]+host_latent[host_id]+identity_latent[identity_id]+
 .24*rng.normal(size=n))
# Select intercept to yield about 5.7% positives; finite sample prevalence fluctuates modestly.
lo,hi=-17.,4.
for _ in range(70):
 mid=(lo+hi)/2; pp=1/(1+np.exp(-np.clip(raw+mid,-40,40)))
 if pp.mean()>.057:hi=mid
 else:lo=mid
risk=1/(1+np.exp(-np.clip(raw+(lo+hi)/2,-40,40)))
y=(rng.random(n)<risk).astype(int)
# Detector severity is noisy *pre-alert* rule score, not an outcome field.
sevscore=(.31*(reputation-30)/23+.24*(endpoint-40)/18+.24*np.log1p(failures)+
 .30*unknown_port+.18*offhours+rng.normal(0,.85,n))
severity=np.where(sevscore>2.3,'critical',np.where(sevscore>1.65,'high',np.where(sevscore>.85,'medium','low')))
# Measurement omissions reflect the source systems, with some correlation to environments.
def missing(values,mask):
 a=np.array(values,dtype='object');a[mask]='';return a
endpoint_obs=missing(np.round(endpoint,1),(rng.random(n)<.03+.08*(family=='email')+.04*(kind=='network_device')))
reputation_obs=missing(np.round(reputation,1),(rng.random(n)<.04+.07*(remote_reg=='unknown')))
geo_obs=missing(np.round(geo_velocity,1),(rng.random(n)<.085+.10*(family=='endpoint')+.08*(remote_reg=='unknown')))
patch_obs=missing(np.rint(patch).astype(int),(rng.random(n)<.045+.14*(kind=='mobile')+.12*(kind=='network_device')))
region_obs=missing(remote_reg,(rng.random(n)<.025+.08*(environment=='on_prem')))
device_obs=missing(kind,(rng.random(n)<.025+.09*(family=='email')))
fail_obs=missing(failures,(rng.random(n)<.025+.11*(family=='network')))
# Leakage examples: case closure fields created after label investigation.
case_codes=np.empty(n,dtype='object')
positive_codes=np.array(['confirmed_malicious','confirmed_policy_violation','confirmed_compromise'])
negative_codes=np.array(['benign_activity','false_positive','approved_change','insufficient_evidence'])
case_codes[y==1]=rng.choice(positive_codes,(y==1).sum(),p=[.64,.13,.23])
case_codes[y==0]=rng.choice(negative_codes,(y==0).sum(),p=[.51,.27,.14,.08])
# Small number of case records remain pending; missingness in aftermath not uniformly random.
case_codes[rng.random(n)<.024]='pending_review'
remed=np.array(['none']*n,dtype='object')
remed[y==1]=rng.choice(['isolate_host','reset_identity','block_indicator','investigate_only'],(y==1).sum(),p=[.27,.26,.34,.13])
remed[(y==0)&(rng.random(n)<.035)]='precautionary_review'
forensic=np.clip(np.round(21+68*y+14*rng.normal(size=n),1),0,100)
# Post-review timestamps are intentionally not contemporaneous to alerts.
closure_days=np.clip(rng.lognormal(1.15,.85,n)*(1+1.2*y),.04,125)
closed=(times.astype('datetime64[m]')+(closure_days*24*60).astype('timedelta64[m]'))
closed_obs=missing(np.datetime_as_string(closed,unit='m'),rng.random(n)<.024)

headers=['alert_id','alert_created_at','tenant_id','host_id','identity_id','deployment_environment','site_region','device_type','operating_system','detection_family','log_source','account_privilege','asset_criticality','detector_severity','source_ip_region','mfa_enabled','new_device_last_30d','off_hours_activity','external_ip_reputation','endpoint_risk_score','failed_auth_attempts_24h','successful_auths_24h','distinct_source_ips_24h','external_connections_1h','outbound_mb_1h','inbound_mb_1h','unusual_destination_port','geo_velocity_kmh','days_since_patch','account_age_days','prior_alerts_90d','alert_burst_count_1h','case_disposition','remediation_action','forensic_score_after_review','case_closed_at','confirmed_incident']
path=Path(__file__).resolve().parents[1] / 'Enterprise_Security_Alerts_Classification.csv'
with path.open('w',newline='',encoding='utf-8') as f:
 writer=csv.writer(f);writer.writerow(headers)
 for i in range(n):
  vals=[f'ALR-{i+1:07d}',str(times[i]).replace('T',' '),f'TNT-{tenant_id[i]:04d}',f'HST-{host_id[i]:05d}',f'USR-{identity_id[i]:05d}',environment[i],site_reg[i],device_obs[i],os[i],family[i],log_source[i],priv[i],asset[i],severity[i],region_obs[i],mfa[i],new_device[i],offhours[i],reputation_obs[i],endpoint_obs[i],fail_obs[i],successes[i],uniqueips[i],connections[i],round(outbound[i],2),round(inbound[i],2),unknown_port[i],geo_obs[i],patch_obs[i],int(account_age[i]),prior[i],alert_burst[i],case_codes[i],remed[i],forensic[i],closed_obs[i],y[i]]
  writer.writerow(vals)

from collections import Counter
cc=Counter(y); missing_ct={k:0 for k in headers}
with path.open(newline='',encoding='utf-8') as f:
 for row in csv.DictReader(f):
  for k,v in row.items():
   if not v:missing_ct[k]+=1
print('path',path,'bytes',path.stat().st_size,'shape',n,len(headers),'counts',cc,'rate',round(y.mean(),5))
print('missing', {k: v for k,v in missing_ct.items() if v})
print('trainval test prevalence by date quarters',[(a,b,int(((month>=a)&(month<b)).sum()),round(float(y[(month>=a)&(month<b)].mean()),4)) for a,b in [(0,12),(12,18),(18,24)]])
