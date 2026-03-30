import streamlit as st
import pandas as pd
import json
import plotly.express as px

from scanner import bulk_scan, enterprise_score

st.set_page_config(page_title="Quantum Scanner", layout="wide")

st.sidebar.title("Navigation")
menu = st.sidebar.radio("Menu", ["Scanner", "Dashboard", "Export"])

if menu == "Scanner":

    st.title("Quantum Security Scanner")

    targets_text = st.text_area("Targets", "google.com\ncloudflare.com")
    deep_scan = st.checkbox("Deep Scan")

    if st.button("Run Scan"):
        targets = [t.strip() for t in targets_text.split("\n") if t.strip()]

        with st.spinner("Scanning..."):
            results = bulk_scan(targets, deep_scan)

        st.session_state["results"] = results

        df = pd.DataFrame(results)
        st.dataframe(df)

        st.bar_chart(df.set_index("endpoint")["score"])

        for r in results:
            with st.expander(r["endpoint"]):
                st.write(r)

elif menu == "Dashboard":

    st.title("Enterprise Dashboard")

    if "results" in st.session_state:
        results = st.session_state["results"]

        df = pd.DataFrame(results)

        st.metric("Enterprise Score", enterprise_score(results))

        fig = px.pie(df, names="grade")
        st.plotly_chart(fig)

elif menu == "Export":

    if "results" in st.session_state:
        results = st.session_state["results"]

        st.download_button("JSON", json.dumps(results, indent=4))

        df = pd.DataFrame(results)
        st.download_button("CSV", df.to_csv(index=False))