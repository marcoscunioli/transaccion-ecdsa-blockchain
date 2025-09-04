#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Script desarrollado por Marcos Sebastián Cunioli – Especialista en Ciberseguridad
#
# Transacción con firma ECDSA secp256k1 (estilo Bitcoin, simplificada para clase)
# Requiere instalar dependencias:
#   pip install ecdsa base58
#
# Ejecutar con:
#   streamlit run tx_ecdsa_secp256k1_streamlit.py

import streamlit as st
import hashlib, json, time, secrets
from dataclasses import dataclass, asdict

st.set_page_config(page_title="Transacción ECDSA (secp256k1)", page_icon="🔑", layout="centered")
st.markdown("### **Marcos Cunioli** – *Especialista en Ciberseguridad*")
st.title("🔑 Transacción con Firma ECDSA (secp256k1)")
st.caption("Claves reales, dirección Base58Check, firma y verificación con ECDSA. *Propósito educativo.*")

# Dependencias externas
try:
    import base58
    from ecdsa import SigningKey, SECP256k1
except Exception as e:
    st.error("Faltan dependencias: instalá con `pip install ecdsa base58` y volvé a ejecutar.")
    st.stop()

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def ripemd160(b: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(b)
    return h.digest()

def sha256d(b: bytes) -> bytes:
    return sha256(sha256(b))

def pubkey_to_address_uncompressed(pubkey_bytes: bytes, version: bytes=b"\x6f") -> str:
    """Dirección estilo Bitcoin (P2PKH simplificada). Versión 0x6f ~ testnet-like."""
    h160 = ripemd160(sha256(pubkey_bytes))
    payload = version + h160
    checksum = sha256d(payload)[:4]
    return base58.b58encode(payload + checksum).decode()

@dataclass
class TxInput:
    prev_txid: str
    index: int

@dataclass
class TxOutput:
    address: str
    amount: int

@dataclass
class Transaction:
    version: int
    timestamp: int
    vin: list
    vout: list
    memo: str = ""

    def serialize(self) -> bytes:
        obj = {
            "version": self.version,
            "timestamp": self.timestamp,
            "vin": [asdict(i) for i in self.vin],
            "vout": [asdict(o) for o in self.vout],
            "memo": self.memo
        }
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def txid(self) -> str:
        return sha256d(self.serialize()).hex()

# --- Estado ---
if "sk_hex" not in st.session_state:
    st.session_state.sk_hex = None
if "vk_hex" not in st.session_state:
    st.session_state.vk_hex = None
if "address" not in st.session_state:
    st.session_state.address = None
if "signature" not in st.session_state:
    st.session_state.signature = None
if "orig_digest" not in st.session_state:
    st.session_state.orig_digest = None
if "orig_tx_json" not in st.session_state:
    st.session_state.orig_tx_json = None

with st.sidebar:
    st.header("🎛️ Claves y Dirección")
    if st.button("🗝️ Generar par de claves ECDSA (secp256k1)", use_container_width=True):
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.get_verifying_key()
        pub_uncompressed = b"\x04" + vk.to_string()
        addr = pubkey_to_address_uncompressed(pub_uncompressed, version=b"\x6f")  # testnet-like
        st.session_state.sk_hex = sk.to_string().hex()
        st.session_state.vk_hex = pub_uncompressed.hex()
        st.session_state.address = addr
        st.session_state.signature = None
        st.session_state.orig_digest = None
        st.session_state.orig_tx_json = None

    if st.session_state.sk_hex:
        st.caption("Clave privada (hex)")
        st.code(st.session_state.sk_hex, language="text")
    if st.session_state.vk_hex:
        st.caption("Clave pública (uncompressed, hex)")
        st.code(st.session_state.vk_hex, language="text")
    if st.session_state.address:
        st.caption("Dirección (Base58Check, testnet-like)")
        st.code(st.session_state.address, language="text")

st.subheader("🧩 Construcción de la Transacción")
col1, col2 = st.columns(2)
with col1:
    prev_txid = st.text_input("TX previa (prev_txid)", value=("b2"*32))
with col2:
    index = st.number_input("Índice del output previo (index)", min_value=0, value=1, step=1)

col3, col4 = st.columns(2)
with col3:
    addr_1 = st.text_input("Dirección destino #1", value=(st.session_state.address or "mjDemoAddr1111"))
    amt_1 = st.number_input("Monto #1 (unidades)", min_value=0, value=25000, step=500)
with col4:
    addr_2 = st.text_input("Dirección destino #2 (opcional)", value="mk2QpYatsKicvFJ4s8uL2r8vDemoAddr1")
    amt_2 = st.number_input("Monto #2 (unidades)", min_value=0, value=5000, step=500)

memo = st.text_input("Memo (comentario)", value="Pago de prueba ECDSA")

can_build = all([st.session_state.sk_hex, st.session_state.vk_hex, st.session_state.address])
if st.button("✍️ Construir & Firmar (ECDSA)", use_container_width=True, disabled=not can_build):
    sk = SigningKey.from_string(bytes.fromhex(st.session_state.sk_hex), curve=SECP256k1)
    tx = Transaction(
        version=1,
        timestamp=int(time.time()),
        vin=[TxInput(prev_txid=prev_txid, index=int(index))],
        vout=[TxOutput(address=addr_1, amount=int(amt_1))] + ([TxOutput(address=addr_2, amount=int(amt_2))] if addr_2 and amt_2>0 else []),
        memo=memo
    )
    ser = tx.serialize()
    txid = tx.txid()
    digest = sha256d(ser)
    signature = sk.sign_digest(digest)  # bytes

    st.session_state.signature = signature.hex()
    st.session_state.orig_digest = digest.hex()
    st.session_state.orig_tx_json = json.loads(ser.decode("utf-8"))

    st.success("Transacción construida y firmada (ECDSA real).")
    st.json(st.session_state.orig_tx_json)
    st.code(f"TXID: {txid}", language="text")
    st.code(f"Digest (double-SHA256): {digest.hex()}", language="text")
    st.code(f"Firma ECDSA (hex): {st.session_state.signature}", language="text")

st.divider()
st.subheader("🧪 Verificación y Alteración")

alter_memo = st.text_input("Alterar memo (prueba de integridad)", value=memo)
verify_click = st.button("🔍 Verificar con firma original (ECDSA)", use_container_width=True, disabled=(st.session_state.signature is None))

if verify_click and st.session_state.orig_tx_json is not None:
    from ecdsa import VerifyingKey
    try:
        tx_json = dict(st.session_state.orig_tx_json)  # copia
        tx_json["memo"] = alter_memo
        ser2 = json.dumps(tx_json, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        digest2 = sha256d(ser2)

        # reconstruir VK desde la pública uncompressed (0x04 + X + Y)
        pub_bytes = bytes.fromhex(st.session_state.vk_hex)
        if pub_bytes[0] != 0x04:
            raise ValueError("Formato de clave pública inesperado.")
        vk = VerifyingKey.from_string(pub_bytes[1:], curve=SECP256k1)
        ok = vk.verify_digest(bytes.fromhex(st.session_state.signature), digest2)

        st.json(tx_json)
        st.code(f"Digest nuevo: {digest2.hex()}", language="text")
        st.warning("Verificación con firma original: **OK** ✅" if ok else "Verificación con firma original: **FALLÓ** ❌")
        if not ok:
            st.caption("Cualquier cambio en el contenido cambia el hash y la firma deja de ser válida.")
    except Exception as e:
        st.error(f"Error al verificar: {e}")
elif st.session_state.signature is None:
    st.info("Primero generá la transacción y la firma para poder verificar.")
