import os

with open('app/pages/3_Live_Battle.py', 'r', encoding='utf-8') as f:
    content = f.read()

metrics_code = '''st.divider()

# --- Metrics Row ---
events = st.session_state.get("battle_events", [])
campaigns = st.session_state.get("battle_campaigns", [])
latest = pd.DataFrame(events) if events else pd.DataFrame()
current_evasion = 1.0 - (latest["Detected"].mean() if not latest.empty else 0.0)
plateaued = st.session_state.get("battle_results", {}).get("plateau_detected", False)

m1, m2, m3, m4 = st.columns(4)
m1.metric("Current step", len(events))
m2.metric("Evasion", f"{current_evasion:.0%}" if events else "---")
m3.metric("Campaigns", len(campaigns))
m4.metric("Plateau", "Detected" if plateaued else "Monitoring")

if plateaued:
    st.warning("Defense-evasion plateau detected across completed campaigns. "
               "The report will include this DVS signal.")

# --- Main Content: Event Log ---'''

content = content.replace('st.divider()\n# --- Main Content: Event Log ---', metrics_code)

with open('app/pages/3_Live_Battle.py', 'w', encoding='utf-8') as f:
    f.write(content)
