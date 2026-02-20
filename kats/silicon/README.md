# KATs — Silicon Power Chips

Known-Answer Tests for the `ubl/silicon.*` chip family.

## The Loop

```
1. POST silicon_bit_always_allow.json       → receipt with bit CID (b3:...)
2. POST silicon_bit_context_equals.json     → receipt with bit CID (b3:...)
3. POST silicon_circuit_sequential_all.json → (update bits[] with real CIDs) → circuit CID
4. POST silicon_chip_payment_gate.json      → (update circuits[] with circuit CID) → chip CID
5. POST silicon_compile_rb_vm.json         → (update chip_cid) → receipt.silicon_compile.bytecode_cid
6. Use bytecode_cid in @tr.bytecode_hex on any future chip → runs your compiled logic in rb_vm
```

## End-to-End Test (gate running on :4000)

```bash
# Step 1 — bit: always allow
BIT1=$(curl -sf -X POST http://localhost:4000/v1/chips \
  -H "Content-Type: application/json" \
  -d @silicon_bit_always_allow.json | jq -r '.cid')
echo "Bit CID: $BIT1"

# Step 2 — bit: is_admin
BIT2=$(curl -sf -X POST http://localhost:4000/v1/chips \
  -H "Content-Type: application/json" \
  -d @silicon_bit_context_equals.json | jq -r '.cid')
echo "Bit CID: $BIT2"

# Step 3 — circuit (wire the two bits)
CIRCUIT=$(curl -sf -X POST http://localhost:4000/v1/chips \
  -H "Content-Type: application/json" \
  -d "{\"@type\":\"ubl/silicon.circuit\",\"@world\":\"a/lab/t/dev\",
       \"id\":\"C_Test\",\"name\":\"Test Circuit\",
       \"bits\":[\"$BIT1\",\"$BIT2\"],
       \"composition\":\"Sequential\",\"aggregator\":\"All\"}" | jq -r '.cid')
echo "Circuit CID: $CIRCUIT"

# Step 4 — chip
CHIP=$(curl -sf -X POST http://localhost:4000/v1/chips \
  -H "Content-Type: application/json" \
  -d "{\"@type\":\"ubl/silicon.chip\",\"@world\":\"a/lab/t/dev\",
       \"id\":\"CHIP_Test\",\"name\":\"Test Chip\",
       \"circuits\":[\"$CIRCUIT\"],
       \"hal\":{\"profile\":\"HAL/v0/cpu\",\"targets\":[\"rb_vm/v1\"],\"deterministic\":true},
       \"version\":\"1.0\"}" | jq -r '.cid')
echo "Chip CID: $CHIP"

# Step 5 — compile
RECEIPT=$(curl -sf -X POST http://localhost:4000/v1/chips \
  -H "Content-Type: application/json" \
  -d "{\"@type\":\"ubl/silicon.compile\",\"@world\":\"a/lab/t/dev\",
       \"chip_cid\":\"$CHIP\",\"target\":\"rb_vm\"}")
echo "Compile receipt:"
echo "$RECEIPT" | jq '{bytecode_cid: .silicon_compile.bytecode_cid, bytecode_len: .silicon_compile.bytecode_len}'
```

## Determinism Check

The same chip definition **always** produces the same CID (BLAKE3 of NRF-1).
The same chip graph **always** compiles to the same bytecode CID.
This is the silicon power: text → CID → bytecode → execution → receipt. Forever.
