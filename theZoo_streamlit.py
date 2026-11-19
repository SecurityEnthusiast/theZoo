import streamlit as st
from typing import List, Tuple

from imports.db_handler import DBHandler
from imports.eula_handler import EULA
from imports import globals


@st.cache_resource
def _get_db() -> DBHandler:
    return DBHandler()


def _load_partial() -> List[Tuple]:
    return _get_db().get_partial_details()


def _load_details(mal_id: int) -> List[Tuple]:
    return _get_db().get_mal_info(mal_id)


def _eula_gate() -> bool:
    globals.init()
    if EULA().check_eula_file():
        return True

    st.title("theZoo – EULA")
    st.warning(
        "This program contains live and dangerous malware files.\n\n"
        "This program is intended to be used only for malware analysis and "
        "research, and by agreeing to the EULA you agree to use it only for "
        "legal purposes and for studying malware.\n\n"
        "You understand that these files are dangerous and should only be "
        "run on VMs you can control and know how to handle. Running them on "
        "a live system will infect your machine with live and dangerous "
        "malware!"
    )
    if st.button("I accept the EULA"):
        with open(globals.vars.eula_file, 'a') as f:
            f.write('YES')
        st.rerun()
    return False


def main() -> None:
    st.set_page_config(page_title="theZoo Streamlit", layout="wide")

    if not _eula_gate():
        return

    st.title("theZoo – Malware DB (Streamlit)")

    search = st.text_input("Filter by any field")

    rows = _load_partial()
    if search:
        q = search.lower().strip()
        if q:
            rows = [
                row for row in rows
                if any(q in str(value).lower() for value in row)
            ]

    if not rows:
        st.info("No results.")
        return

    table_rows = [
        {
            "ID": row[0],
            "Type": row[1],
            "Language": row[2],
            "Architecture": row[3],
            "Platform": row[4],
            "Name": row[5],
        }
        for row in rows
    ]

    st.dataframe(table_rows, hide_index=True, use_container_width=True)

    ids = [row["ID"] for row in table_rows]
    selected_id = st.selectbox("Select malware ID for details", ids)

    if selected_id is None:
        return

    details = _load_details(int(selected_id))
    if not details:
        st.warning("No additional metadata found for this entry.")
        return

    (
        mal_type,
        name,
        version,
        author,
        language,
        date,
        architecture,
        platform,
        tags,
    ) = details[0]

    st.subheader("Details")
    st.write({
        "Name": name,
        "Type": mal_type,
        "Version": version,
        "Author": author,
        "Language": language,
        "Date": date,
        "Architecture": architecture,
        "Platform": platform,
        "Tags": tags,
    })


if __name__ == "__main__":
    main()
