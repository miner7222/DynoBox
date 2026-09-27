use super::*;

#[test]
fn parse_descriptor_no_args_bool() {
    assert_eq!(parse_method_descriptor("()Z"), Some(("Z".into(), vec![])));
}

#[test]
fn parse_descriptor_one_object_arg() {
    assert_eq!(
        parse_method_descriptor("(Landroid/content/Context;)Ljava/util/ArrayList;"),
        Some((
            "Ljava/util/ArrayList;".into(),
            vec!["Landroid/content/Context;".into()]
        ))
    );
}

#[test]
fn parse_descriptor_array_and_primitive_args() {
    assert_eq!(
        parse_method_descriptor("([Ljava/lang/String;IJ)V"),
        Some((
            "V".into(),
            vec!["[Ljava/lang/String;".into(), "I".into(), "J".into()]
        ))
    );
}

#[test]
fn parse_descriptor_rejects_malformed() {
    assert_eq!(parse_method_descriptor("Z"), None);
    assert_eq!(parse_method_descriptor("()"), None);
    assert_eq!(parse_method_descriptor("(L)Z"), None);
}

#[test]
fn method_code_replacement_requires_whole_equal_size_instructions() {
    let valid = MethodCodeReplacement {
        from: &[0x12, 0x00, 0x0e, 0x00],
        to: &[0x12, 0x01, 0x0e, 0x00],
        expected: 1,
    };
    assert!(validate_method_code_replacement(&valid).is_ok());

    let truncated = MethodCodeReplacement {
        from: &[0x29, 0x00],
        to: &[0x00, 0x00],
        expected: 1,
    };
    assert!(validate_method_code_replacement(&truncated).is_err());

    let resized = MethodCodeReplacement {
        from: &[0x00, 0x00],
        to: &[0x00, 0x00, 0x00, 0x00],
        expected: 1,
    };
    assert!(validate_method_code_replacement(&resized).is_err());

    let unchanged = MethodCodeReplacement {
        from: &[0x00, 0x00],
        to: &[0x00, 0x00],
        expected: 1,
    };
    assert!(validate_method_code_replacement(&unchanged).is_err());
}

#[test]
fn method_code_control_flow_rejects_mid_instruction_branch() {
    // goto/16 +2 code units lands on the return-void instruction.
    assert!(validate_method_control_flow(&[0x29, 0x00, 0x02, 0x00, 0x0e, 0x00]).is_ok());
    // +1 code unit lands in goto/16's own signed-offset operand.
    assert!(validate_method_control_flow(&[0x29, 0x00, 0x01, 0x00, 0x0e, 0x00]).is_err());
}

#[test]
fn method_code_replacement_refuses_invoke_with_consumed_result() {
    let insns = [
        0x12, 0x02, // const/4 v2, #0
        0x71, 0x30, 0x34, 0x12, 0x10, 0x02, // invoke-static {v0,v1,v2}
        0x0a, 0x00, // move-result v0
        0x0e, 0x00, // return-void
    ];
    let replacement = [0x12, 0x02, 0x13, 0x04, 0x08, 0x00, 0x00, 0x00];
    assert!(replacement_overwrites_consumed_invoke(&insns, 0, &replacement).unwrap());

    let discarded = &insns[..8];
    assert!(!replacement_overwrites_consumed_invoke(discarded, 0, &replacement).unwrap());

    let covered_consumer = [
        0x12, 0x02, // const/4 v2, #0
        0x13, 0x04, 0x08, 0x00, // const/16 v4, #8
        0x00, 0x00, // nop
        0x00, 0x00, // replace the move-result too
    ];
    assert!(!replacement_overwrites_consumed_invoke(&insns, 0, &covered_consumer).unwrap());

    let filled_array = [
        0x24, 0x20, 0x34, 0x12, 0x10, 0x00, // filled-new-array {v0,v1}
        0x0c, 0x02, // move-result-object v2
    ];
    let remove_filled_array = [0x12, 0x02, 0x00, 0x00, 0x00, 0x00];
    assert!(
        replacement_overwrites_consumed_invoke(&filled_array, 0, &remove_filled_array).unwrap()
    );
}

#[test]
fn method_code_result_flow_checks_changed_producer_types() {
    let header = DexHeader {
        string_ids_size: 4,
        string_ids_off: 0,
        type_ids_size: 4,
        type_ids_off: 16,
        proto_ids_size: 4,
        proto_ids_off: 32,
        field_ids_size: 0,
        field_ids_off: 0,
        method_ids_size: 4,
        method_ids_off: 80,
        class_defs_size: 0,
        class_defs_off: 0,
    };
    let mut dex = vec![0u8; 128];
    for (index, descriptor) in ["I", "V", "J", "Ljava/lang/Object;"].iter().enumerate() {
        let string_off = dex.len();
        dex.push(u8::try_from(descriptor.len()).unwrap());
        dex.extend_from_slice(descriptor.as_bytes());
        dex.push(0);
        dex[index * 4..index * 4 + 4]
            .copy_from_slice(&u32::try_from(string_off).unwrap().to_le_bytes());
        dex[16 + index * 4..20 + index * 4]
            .copy_from_slice(&u32::try_from(index).unwrap().to_le_bytes());
        dex[36 + index * 12..40 + index * 12]
            .copy_from_slice(&u32::try_from(index).unwrap().to_le_bytes());
        dex[82 + index * 8..84 + index * 8]
            .copy_from_slice(&u16::try_from(index).unwrap().to_le_bytes());
    }

    let invoke = |method_idx: u16, result_opcode: u8, register_byte: u8| {
        let [lo, hi] = method_idx.to_le_bytes();
        [
            0x71,
            register_byte,
            lo,
            hi,
            0x00,
            0x00,
            result_opcode,
            0x00,
            0x0e,
            0x00,
        ]
    };
    let original = invoke(0, 0x0a, 0x00);

    let changed_scalar = invoke(0, 0x0a, 0x10);
    assert!(validate_move_result_producers(&dex, &header, &original, &changed_scalar).unwrap());
    let changed_wide = invoke(2, 0x0b, 0x00);
    assert!(validate_move_result_producers(&dex, &header, &original, &changed_wide).unwrap());
    let changed_object = invoke(3, 0x0c, 0x00);
    assert!(validate_move_result_producers(&dex, &header, &original, &changed_object).unwrap());

    let void_with_result = invoke(1, 0x0a, 0x00);
    assert!(!validate_move_result_producers(&dex, &header, &original, &void_with_result).unwrap());
    let wide_with_scalar_result = invoke(2, 0x0a, 0x00);
    assert!(
        !validate_move_result_producers(&dex, &header, &original, &wide_with_scalar_result)
            .unwrap()
    );
    let dangling = [
        0x12, 0x00, // const/4 v0, #0
        0x00, 0x00, // nop
        0x00, 0x00, // nop
        0x0a, 0x00, // dangling move-result v0
        0x0e, 0x00, // return-void
    ];
    assert!(!validate_move_result_producers(&dex, &header, &original, &dangling).unwrap());

    let original_array = invoke(3, 0x0c, 0x00);
    let filled_array = [
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, // filled-new-array {}
        0x0c, 0x00, // move-result-object v0
        0x0e, 0x00, // return-void
    ];
    assert!(validate_move_result_producers(&dex, &header, &original_array, &filled_array).unwrap());

    let original_polymorphic = [
        0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // proto@0 -> I
        0x0a, 0x00, // move-result v0
        0x0e, 0x00, // return-void
    ];
    let object_polymorphic = [
        0xfa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, // proto@3 -> Object
        0x0c, 0x00, // move-result-object v0
        0x0e, 0x00, // return-void
    ];
    assert!(
        validate_move_result_producers(&dex, &header, &original_polymorphic, &object_polymorphic,)
            .unwrap()
    );

    let custom = [
        0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, // invoke-custom {}
        0x0a, 0x00, // move-result v0
        0x0e, 0x00, // return-void
    ];
    assert!(validate_move_result_producers(&dex, &header, &custom, &custom).unwrap());
    let mut changed_custom = custom;
    changed_custom[1] = 0x10;
    assert!(!validate_move_result_producers(&dex, &header, &custom, &changed_custom).unwrap());
}

fn synthetic_redirect_fixture(
    target_code_off: usize,
    donor_code_off: usize,
) -> (Vec<u8>, EncodedMethod, EncodedMethod) {
    let mut dex = vec![0u8; donor_code_off.max(target_code_off) + 32];
    for code_off in [target_code_off, donor_code_off] {
        dex[code_off..code_off + 2].copy_from_slice(&1u16.to_le_bytes());
        dex[code_off + 2..code_off + 4].copy_from_slice(&1u16.to_le_bytes());
        dex[code_off + 12..code_off + 16].copy_from_slice(&2u32.to_le_bytes());
        dex[code_off + 16..code_off + 20].copy_from_slice(&[0x12, 0x00, 0x0f, 0x00]);
    }
    let (old_encoded, old_width) = encode_uleb128_u32(target_code_off as u32);
    dex[8..8 + old_width].copy_from_slice(&old_encoded[..old_width]);
    (
        dex,
        EncodedMethod {
            method_idx: 1,
            code_off: target_code_off,
            code_off_field_off: 8,
            code_off_width: old_width,
        },
        EncodedMethod {
            method_idx: 2,
            code_off: donor_code_off,
            code_off_field_off: 16,
            code_off_width: encode_uleb128_u32(donor_code_off as u32).1,
        },
    )
}

fn synthetic_shape_header() -> DexHeader {
    DexHeader {
        string_ids_size: 0,
        string_ids_off: 0,
        type_ids_size: 1,
        type_ids_off: 0,
        proto_ids_size: 0,
        proto_ids_off: 0,
        field_ids_size: 0,
        field_ids_off: 0,
        method_ids_size: 0,
        method_ids_off: 0,
        class_defs_size: 0,
        class_defs_off: 0,
    }
}

fn write_u32(dex: &mut [u8], off: usize, value: u32) {
    dex[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn append_dex_string(dex: &mut Vec<u8>, value: &str) -> u32 {
    let off = u32::try_from(dex.len()).unwrap();
    dex.push(u8::try_from(value.len()).unwrap());
    dex.extend_from_slice(value.as_bytes());
    dex.push(0);
    off
}

fn synthetic_public_redirect_dex() -> Vec<u8> {
    const STRING_IDS_OFF: usize = 0x70;
    const TYPE_IDS_OFF: usize = 0x84;
    const PROTO_IDS_OFF: usize = 0x90;
    const METHOD_IDS_OFF: usize = 0x9c;
    const CLASS_DEFS_OFF: usize = 0xb4;
    const TARGET_CLASS_DATA_OFF: usize = 0x120;
    const DONOR_CLASS_DATA_OFF: usize = 0x128;
    const TARGET_CODE_OFF: usize = 0x140;
    const DONOR_CODE_OFF: usize = 0x180;

    let mut dex = vec![0u8; 0xf4];
    for (off, value) in [
        (0x38, 5u32),
        (0x3c, STRING_IDS_OFF as u32),
        (0x40, 3),
        (0x44, TYPE_IDS_OFF as u32),
        (0x48, 1),
        (0x4c, PROTO_IDS_OFF as u32),
        (0x50, 0),
        (0x54, 0),
        (0x58, 2),
        (0x5c, METHOD_IDS_OFF as u32),
        (0x60, 2),
        (0x64, CLASS_DEFS_OFF as u32),
    ] {
        write_u32(&mut dex, off, value);
    }

    let strings = ["LTarget;", "LDonor;", "I", "target", "donor"];
    for (idx, value) in strings.into_iter().enumerate() {
        let string_off = append_dex_string(&mut dex, value);
        write_u32(&mut dex, STRING_IDS_OFF + idx * 4, string_off);
    }
    dex.resize(DONOR_CODE_OFF + 20, 0);

    for (idx, descriptor_idx) in [0u32, 1, 2].into_iter().enumerate() {
        write_u32(&mut dex, TYPE_IDS_OFF + idx * 4, descriptor_idx);
    }
    write_u32(&mut dex, PROTO_IDS_OFF + 4, 2);

    dex[METHOD_IDS_OFF..METHOD_IDS_OFF + 2].copy_from_slice(&0u16.to_le_bytes());
    dex[METHOD_IDS_OFF + 2..METHOD_IDS_OFF + 4].copy_from_slice(&0u16.to_le_bytes());
    write_u32(&mut dex, METHOD_IDS_OFF + 4, 3);
    dex[METHOD_IDS_OFF + 8..METHOD_IDS_OFF + 10].copy_from_slice(&1u16.to_le_bytes());
    dex[METHOD_IDS_OFF + 10..METHOD_IDS_OFF + 12].copy_from_slice(&0u16.to_le_bytes());
    write_u32(&mut dex, METHOD_IDS_OFF + 12, 4);

    write_u32(&mut dex, CLASS_DEFS_OFF, 0);
    write_u32(&mut dex, CLASS_DEFS_OFF + 24, TARGET_CLASS_DATA_OFF as u32);
    write_u32(&mut dex, CLASS_DEFS_OFF + 32, 1);
    write_u32(
        &mut dex,
        CLASS_DEFS_OFF + 32 + 24,
        DONOR_CLASS_DATA_OFF as u32,
    );

    for (class_data_off, method_idx, code_off) in [
        (TARGET_CLASS_DATA_OFF, 0u8, TARGET_CODE_OFF as u32),
        (DONOR_CLASS_DATA_OFF, 1u8, DONOR_CODE_OFF as u32),
    ] {
        dex[class_data_off..class_data_off + 6].copy_from_slice(&[0, 0, 1, 0, method_idx, 1]);
        let (encoded, width) = encode_uleb128_u32(code_off);
        dex[class_data_off + 6..class_data_off + 6 + width].copy_from_slice(&encoded[..width]);
    }

    for (code_off, literal) in [(TARGET_CODE_OFF, 0u8), (DONOR_CODE_OFF, 3u8)] {
        dex[code_off..code_off + 2].copy_from_slice(&1u16.to_le_bytes());
        write_u32(&mut dex, code_off + 12, 2);
        dex[code_off + 16..code_off + 20].copy_from_slice(&[0x12, literal << 4, 0x0f, 0x00]);
    }
    dex
}

const TARGET_REF: DexMethodRef<'static> = DexMethodRef {
    class: "LTarget;",
    name: "target",
    ret: "I",
    params: &[],
};
const DONOR_REF: DexMethodRef<'static> = DexMethodRef {
    class: "LDonor;",
    name: "donor",
    ret: "I",
    params: &[],
};

#[test]
fn dex_ops_survive_mutated_input() {
    let seed = synthetic_public_redirect_dex();
    dynobox_core::testutil::for_each_mutation(&seed, 0xDE70, 3000, |bytes| {
        let mut dex = bytes.to_vec();
        let _ = redirect_method_code(&mut dex, TARGET_REF, DONOR_REF);
        let mut dex = bytes.to_vec();
        let _ = force_method_return_int(&mut dex, "LTarget;", "target", "I", &[], 7);
        let mut dex = bytes.to_vec();
        let _ = force_method_return_void(&mut dex, "LTarget;", "target", "I", &[]);
        let mut dex = bytes.to_vec();
        let _ = force_invoke_const_bool(
            &mut dex,
            "LTarget;",
            None,
            "LDonor;",
            "donor",
            "I",
            &[],
            true,
        );
        let _ = crate::fuck_lgsi::dex_walker::extract_lgsi_features(bytes);
    });
}

#[test]
fn method_code_redirect_repoints_same_shape_same_width() {
    let (mut dex, target, donor) = synthetic_redirect_fixture(0x100, 0x180);
    let h = synthetic_shape_header();
    let before_target_body = dex[0x100..0x114].to_vec();
    let before_donor_body = dex[0x180..0x194].to_vec();

    assert!(redirect_compatible_code_off(
        &mut dex, &h, target, donor, "I", "I"
    ));
    assert_eq!(&dex[8..10], &encode_uleb128_u32(0x180).0[..2]);
    assert_eq!(&dex[0x100..0x114], before_target_body);
    assert_eq!(&dex[0x180..0x194], before_donor_body);
}

#[test]
fn method_code_redirect_refuses_shape_mismatch() {
    let (mut dex, target, donor) = synthetic_redirect_fixture(0x100, 0x180);
    let h = synthetic_shape_header();
    dex[0x180 + 4..0x180 + 6].copy_from_slice(&1u16.to_le_bytes());
    let before = dex.clone();

    assert!(!redirect_compatible_code_off(
        &mut dex, &h, target, donor, "I", "I"
    ));
    assert_eq!(dex, before);
}

#[test]
fn method_code_redirect_refuses_different_uleb_width() {
    let (mut dex, target, donor) = synthetic_redirect_fixture(0x40, 0x100);
    let h = synthetic_shape_header();
    let before = dex.clone();

    assert!(!redirect_compatible_code_off(
        &mut dex, &h, target, donor, "I", "I"
    ));
    assert_eq!(dex, before);
}

#[test]
fn redirect_method_code_refuses_truncated_header() {
    let mut dex = vec![0u8; 0x60];
    let before = dex.clone();
    assert!(!redirect_method_code(&mut dex, TARGET_REF, DONOR_REF).unwrap());
    assert_eq!(dex, before);
}

#[test]
fn redirect_method_code_public_api_repoints_valid_fixture() {
    let mut dex = synthetic_public_redirect_dex();
    let before_len = dex.len();
    assert!(redirect_method_code(&mut dex, TARGET_REF, DONOR_REF).unwrap());
    assert_eq!(dex.len(), before_len);
    assert_eq!(&dex[0x126..0x128], &encode_uleb128_u32(0x180).0[..2]);
}

#[test]
fn redirect_method_code_refuses_oversized_encoded_method_index() {
    let mut dex = synthetic_public_redirect_dex();
    dex[0x124..0x129].copy_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x10]);
    let before = dex.clone();
    assert!(redirect_method_code(&mut dex, TARGET_REF, DONOR_REF).is_err());
    assert_eq!(dex, before);
}

#[test]
fn redirect_method_code_refuses_ambiguous_symbol() {
    let mut dex = synthetic_public_redirect_dex();
    write_u32(&mut dex, 0x58, 3);
    let duplicate = dex[0x9c..0xa4].to_vec();
    dex[0xac..0xb4].copy_from_slice(&duplicate);
    let before = dex.clone();
    assert!(!redirect_method_code(&mut dex, TARGET_REF, DONOR_REF).unwrap());
    assert_eq!(dex, before);
}

#[test]
fn redirect_method_code_refuses_malformed_code_item_tail() {
    let mut dex = synthetic_public_redirect_dex();
    dex[0x186..0x188].copy_from_slice(&1u16.to_le_bytes());
    let before = dex.clone();
    assert!(!redirect_method_code(&mut dex, TARGET_REF, DONOR_REF).unwrap());
    assert_eq!(dex, before);
}

#[test]
fn redirect_method_code_refuses_identical_and_missing_methods() {
    let mut dex = synthetic_public_redirect_dex();
    let before = dex.clone();
    assert!(!redirect_method_code(&mut dex, TARGET_REF, TARGET_REF).unwrap());
    let missing = DexMethodRef {
        name: "missing",
        ..TARGET_REF
    };
    assert!(!redirect_method_code(&mut dex, missing, DONOR_REF).unwrap());
    assert_eq!(dex, before);
}

#[test]
fn preference_controller_hide_body_is_size_preserving_and_keeps_field_binding() {
    let refs = PreferenceControllerRefs {
        super_display: 0x1111,
        get_key: 0x2222,
        find_preference: 0x3333,
        switch_type: 0x4444,
        preference_field: 0x5555,
        update_description: 0x6666,
        preference_key: 0x7777,
        set_visible: 0x1234,
    };
    let original = encode_original_preference_controller_body(refs, 1, 2, 0).unwrap();
    let hidden = encode_hidden_preference_controller_body(refs, 1, 2, 0).unwrap();

    assert_eq!(original.len(), 19 * 2);
    assert_eq!(hidden.len(), original.len());
    assert_eq!(&hidden[0..6], &[0x6f, 0x20, 0x11, 0x11, 0x21, 0x00]);
    assert_eq!(&hidden[6..10], &[0x1a, 0x00, 0x77, 0x77]);
    assert!(
        hidden
            .windows(4)
            .any(|window| window == [0x5b, 0x12, 0x55, 0x55]),
        "replacement must preserve the mUserExperience field assignment"
    );
    assert!(
        hidden
            .windows(6)
            .any(|window| window == [0x6e, 0x20, 0x34, 0x12, 0x02, 0x00]),
        "replacement must call Preference.setVisible on the bound preference"
    );
    assert_eq!(&hidden[34..38], &[0x0e, 0x00, 0x00, 0x00]);
    assert!(validate_method_control_flow(&hidden).is_ok());
}

#[test]
fn field_const_bool_rewrites_only_matching_iget_boolean() {
    // iget-boolean v3,v7,field@0x1234; unrelated iget-boolean; return-void
    let mut insns = vec![0x55, 0x73, 0x34, 0x12, 0x55, 0x21, 0x78, 0x56, 0x0e, 0x00];
    let end = insns.len();
    let sites = rewrite_field_bool_sites(&mut insns, 0, end, 0x1234, true);
    assert_eq!(sites, 1);
    assert_eq!(&insns[..4], &[0x12, 0x13, 0x00, 0x00]);
    assert_eq!(&insns[4..8], &[0x55, 0x21, 0x78, 0x56]);
}

#[test]
fn field_const_bool_writes_false_and_missing_field_is_noop() {
    let original = vec![0x55, 0x84, 0x34, 0x12, 0x0e, 0x00];
    let mut false_case = original.clone();
    let false_end = false_case.len();
    assert_eq!(
        rewrite_field_bool_sites(&mut false_case, 0, false_end, 0x1234, false),
        1
    );
    assert_eq!(&false_case[..4], &[0x12, 0x04, 0x00, 0x00]);

    let mut missing = original.clone();
    let missing_end = missing.len();
    assert_eq!(
        rewrite_field_bool_sites(&mut missing, 0, missing_end, 0xabcd, true),
        0
    );
    assert_eq!(missing, original);
}

fn invoke_35c(method_idx: u16, regs: &[u8]) -> [u8; 6] {
    assert!(regs.len() <= 5);
    let mut out = [0u8; 6];
    out[0] = 0x6e;
    out[1] = (regs.len() as u8) << 4;
    out[2..4].copy_from_slice(&method_idx.to_le_bytes());
    if let Some(&reg) = regs.first() {
        out[4] |= reg;
    }
    if let Some(&reg) = regs.get(1) {
        out[4] |= reg << 4;
    }
    if let Some(&reg) = regs.get(2) {
        out[5] |= reg;
    }
    if let Some(&reg) = regs.get(3) {
        out[5] |= reg << 4;
    }
    if let Some(&reg) = regs.get(4) {
        out[1] |= reg;
    }
    out
}

#[test]
fn intent_redirect_locates_exact_action_intent_and_start() {
    const FROM: u32 = 0x1234;
    const SET_ACTION: u16 = 0x20;
    const START: u16 = 0x21;
    let mut insns = vec![0x1a, 0x02, 0x34, 0x12]; // const-string v2, FROM
    insns.extend(invoke_35c(SET_ACTION, &[5, 2])); // setAction(v5,v2)
    insns.extend([0x12, 0x01]); // harmless const/4
    insns.extend(invoke_35c(START, &[7, 5, 9])); // startActivity(v7,v5,v9)
    insns.extend([0x0e, 0x00]);
    let sites = locate_intent_redirect_sites(&insns, 0, insns.len(), FROM, SET_ACTION, START);
    assert_eq!(
        sites,
        vec![IntentRedirectSite {
            string_off: 0,
            string_opcode: 0x1a,
            start_off: 12,
            context_reg: 7,
            intent_reg: 5,
        }]
    );

    write_intent_redirect_site(&mut insns, sites[0], 0x4321, 0x6543);
    assert_eq!(&insns[..4], &[0x1a, 0x02, 0x21, 0x43]);
    assert_eq!(
        &insns[12..18],
        &[0x6e, 0x20, 0x43, 0x65, 0x57, 0x00],
        "sendBroadcast(v7,v5) keeps the three-unit invoke width"
    );
}

#[test]
fn method_broadcast_finish_encodes_super_broadcast_and_finish() {
    let super_idx: u16 = 0x1111;
    let intent_type: u16 = 0x2222;
    let init_idx: u16 = 0x3333;
    let action_idx: u16 = 0x4444;
    let send_bc: u16 = 0x6666;
    let finish: u16 = 0x7777;
    let this_reg: u16 = 2;
    let bundle_reg: u16 = 3;
    let body = encode_method_broadcast_finish_body(
        super_idx,
        finish,
        intent_type,
        u32::from(action_idx),
        init_idx,
        send_bc,
        this_reg,
        bundle_reg,
    );

    assert_eq!(body.len(), 34);
    assert_eq!(&body[0..6], &[0x6f, 0x20, 0x11, 0x11, 0x32, 0x00]);
    assert_eq!(
        &body[6..12],
        &[0x6e, 0x10, 0x77, 0x77, this_reg as u8, 0x00],
        "finish must precede all broadcast work"
    );
    assert_eq!(&body[12..16], &[0x22, 0x00, 0x22, 0x22]);
    assert_eq!(&body[16..20], &[0x1a, 0x01, 0x44, 0x44]);
    assert_eq!(&body[20..26], &[0x70, 0x20, 0x33, 0x33, 0x10, 0x00]);
    assert_eq!(
        &body[26..34],
        &[0x6e, 0x20, 0x66, 0x66, this_reg as u8, 0x00, 0x0e, 0x00]
    );

    let jumbo = encode_method_broadcast_finish_body(
        super_idx,
        finish,
        intent_type,
        0x0001_4444,
        init_idx,
        send_bc,
        this_reg,
        bundle_reg,
    );
    assert_eq!(jumbo.len(), 36);
    assert_eq!(&jumbo[16..22], &[0x1b, 0x01, 0x44, 0x44, 0x01, 0x00]);
}

#[test]
fn intent_redirect_skips_wrong_register_and_keeps_branch_local_starts() {
    const FROM: u32 = 0x1234;
    const SET_ACTION: u16 = 0x20;
    const START: u16 = 0x21;

    let mut wrong = vec![0x1a, 0x02, 0x34, 0x12];
    wrong.extend(invoke_35c(SET_ACTION, &[5, 3])); // action is v3, not v2
    wrong.extend(invoke_35c(START, &[7, 5, 9]));
    assert!(
        locate_intent_redirect_sites(&wrong, 0, wrong.len(), FROM, SET_ACTION, START).is_empty()
    );

    let mut ambiguous = vec![0x1a, 0x02, 0x34, 0x12];
    ambiguous.extend(invoke_35c(SET_ACTION, &[5, 2]));
    ambiguous.extend(invoke_35c(START, &[7, 5, 9]));
    ambiguous.extend(invoke_35c(START, &[7, 5, 8]));
    let sites =
        locate_intent_redirect_sites(&ambiguous, 0, ambiguous.len(), FROM, SET_ACTION, START);
    assert_eq!(sites.len(), 2, "both action-derived launches are matched");
}

fn code_item_with_nops(insns_size: u32) -> Vec<u8> {
    let mut code = vec![0u8; 16 + insns_size as usize * 2];
    code[0..2].copy_from_slice(&1u16.to_le_bytes());
    code[12..16].copy_from_slice(&insns_size.to_le_bytes());
    code
}

#[test]
fn method_const_int_uses_smallest_dalvik_const_encoding() {
    let mut small = code_item_with_nops(4);
    assert!(rewrite_method_body_const_int(&mut small, 0, 1).unwrap());
    assert_eq!(&small[16..20], &[0x12, 0x10, 0x0f, 0x00]);

    let mut medium = code_item_with_nops(4);
    assert!(rewrite_method_body_const_int(&mut medium, 0, 0x1234).unwrap());
    assert_eq!(&medium[16..22], &[0x13, 0x00, 0x34, 0x12, 0x0f, 0x00]);

    let mut full = code_item_with_nops(4);
    assert!(rewrite_method_body_const_int(&mut full, 0, 0x1234_5678).unwrap());
    assert_eq!(
        &full[16..24],
        &[0x14, 0x00, 0x78, 0x56, 0x34, 0x12, 0x0f, 0x00]
    );
}

#[test]
fn method_const_string_emits_const_string_and_return_object() {
    // Body large enough for const-string (2 units) + return-object (1 unit).
    let mut code = code_item_with_nops(4);
    assert!(rewrite_method_body_const_string(&mut code, 0, 0x0d9c).unwrap());
    assert_eq!(
        &code[16..22],
        &[0x1a, 0x00, 0x9c, 0x0d, 0x11, 0x00],
        "const-string v0, string@0d9c / return-object v0"
    );
    assert_eq!(&code[22..24], &[0x00, 0x00], "remainder nop-padded");
}

#[test]
fn method_const_string_preserves_tries_and_trailing_handlers() {
    let mut code = code_item_with_nops(4);
    code[6..8].copy_from_slice(&1u16.to_le_bytes());
    let trailer = [0xAAu8; 12];
    code.extend_from_slice(&trailer);

    assert!(rewrite_method_body_const_string(&mut code, 0, 0x0001).unwrap());

    assert_eq!(
        u16::from_le_bytes([code[6], code[7]]),
        1,
        "tries_size preserved"
    );
    assert_eq!(&code[24..36], &trailer, "try/handler bytes preserved");
}

#[test]
fn method_const_string_refuses_body_without_room_or_registers() {
    // One code unit cannot hold the 3-unit replacement.
    let mut tiny = code_item_with_nops(1);
    assert!(!rewrite_method_body_const_string(&mut tiny, 0, 1).unwrap());

    // registers_size == 0 means v0 does not exist.
    let mut no_regs = code_item_with_nops(4);
    no_regs[0..2].copy_from_slice(&0u16.to_le_bytes());
    assert!(!rewrite_method_body_const_string(&mut no_regs, 0, 1).unwrap());
}

#[test]
fn method_const_string_rejects_non_string_return() {
    let mut dex = synthetic_public_redirect_dex();
    let err = force_method_return_const_string(&mut dex, "Lx/Y;", "m", "I", &[], "CN")
        .expect_err("non-string return must be rejected");
    assert!(err.to_string().contains("Ljava/lang/String;"));
}

#[test]
fn method_const_string_refuses_absent_pool_string() {
    // The string is not in this dex's pool, so no id may be created.
    let mut dex = synthetic_public_redirect_dex();
    assert!(
        !force_method_return_const_string(
            &mut dex,
            "Lx/Y;",
            "m",
            "Ljava/lang/String;",
            &[],
            "a-string-that-is-not-in-the-pool",
        )
        .unwrap()
    );
}

#[test]
fn method_nop_rewrites_body_to_return_void_and_preserves_tries() {
    let mut code = code_item_with_nops(4);
    // tries_size = 1, with trailing try_item + handler bytes after the insns.
    // These must be left byte-identical: zeroing tries_size while the handler
    // bytes remain would desync the dex verifier's contiguous code-item walk.
    code[6..8].copy_from_slice(&1u16.to_le_bytes());
    // First instruction: const v0, #0x1234 (0x14, 3 units = 6 bytes).
    code[16] = 0x14;
    code[17] = 0x00;
    code[18..22].copy_from_slice(&0x1234u32.to_le_bytes());
    // Trailing try/handler region (contents arbitrary; must be preserved).
    let trailer = [0xAAu8; 12];
    code.extend_from_slice(&trailer);

    assert!(rewrite_method_body_return_void(&mut code, 0).unwrap());

    assert_eq!(&code[16..18], &[0x0e, 0x00], "return-void");
    assert_eq!(&code[18..22], &[0x00; 4], "old const nop-padded");
    assert_eq!(
        u16::from_le_bytes([code[6], code[7]]),
        1,
        "tries_size preserved"
    );
    assert_eq!(&code[24..36], &trailer, "try/handler bytes preserved");
}

/// `force_method_return_bool` lands on the real ZuiLauncher
/// `Utilities.isZuiRow()`. Set `DYNOBOX_ZUILAUNCHER_DEX_DIR`.
#[test]
#[ignore = "fixture: set DYNOBOX_ZUILAUNCHER_DEX_DIR"]
fn method_const_lands_on_real_zuilauncher() {
    let dir = crate::test_fixtures::env("DYNOBOX_ZUILAUNCHER_DEX_DIR");
    let dir = std::path::Path::new(&dir);
    let mut hits = 0;
    for name in ["classes.dex", "classes2.dex", "classes3.dex"] {
        let Ok(mut dex) = std::fs::read(dir.join(name)) else {
            continue;
        };
        if force_method_return_bool(
            &mut dex,
            "Lcom/android/launcher3/Utilities;",
            "isZuiRow",
            "Z",
            &[],
            true,
        )
        .expect("patch")
        {
            hits += 1;
        }
    }
    assert_eq!(
        hits, 1,
        "Utilities.isZuiRow should be forced in exactly one dex"
    );
}

/// `force_method_return_int` lands on the real services.jar
/// `PhoneWindowManager.getResolvedLongPressOnPowerBehavior()`.
/// Set `DYNOBOX_SERVICES_ARCHIVE`.
#[test]
#[ignore = "fixture: set DYNOBOX_SERVICES_ARCHIVE"]
fn method_const_int_lands_on_real_services() {
    let path = crate::test_fixtures::env("DYNOBOX_SERVICES_ARCHIVE");
    let archive = std::fs::read(path).expect("read services archive");
    let zip =
        crate::zip_util::parse_zip_central_directory(&archive).expect("parse services archive");
    let mut hits = 0;
    for entry in zip.entries.iter().filter(|entry| {
        entry.name.ends_with(".dex")
            && entry.compression_method == 0
            && !entry.uses_data_descriptor
            && !entry.is_zip64
            && entry.data_start + entry.compressed_size <= archive.len()
    }) {
        let mut dex = archive[entry.data_start..entry.data_start + entry.compressed_size].to_vec();
        if force_method_return_int(
            &mut dex,
            "Lcom/android/server/policy/PhoneWindowManager;",
            "getResolvedLongPressOnPowerBehavior",
            "I",
            &[],
            1,
        )
        .expect("patch")
        {
            hits += 1;
        }
    }
    assert_eq!(hits, 1, "power behavior resolver should be forced once");
}

/// The exact, structure-validated User Experience preference rewrite must
/// land in one real ZuiSettings dex and refuse a second application. Set
/// `DYNOBOX_ZUISETTINGS_DEX_DIR` to extracted original APK dexes.
#[test]
#[ignore = "fixture: set DYNOBOX_ZUISETTINGS_DEX_DIR"]
fn preference_controller_hide_lands_on_real_zuisettings() {
    let dir = crate::test_fixtures::env("DYNOBOX_ZUISETTINGS_DEX_DIR");
    let dir = std::path::Path::new(&dir);
    let mut hits = 0usize;
    for name in [
        "classes.dex",
        "classes2.dex",
        "classes3.dex",
        "classes4.dex",
        "classes5.dex",
        "classes6.dex",
    ] {
        let Ok(mut dex) = std::fs::read(dir.join(name)) else {
            continue;
        };
        let len = dex.len();
        if force_preference_controller_hidden(
            &mut dex,
            "Lcom/lenovo/settings/privacy/UserExperienceSwitchController;",
            "user_experience",
            "mUserExperience",
        )
        .expect("patch")
        {
            hits += 1;
            assert_eq!(dex.len(), len, "DEX length must remain unchanged");
            assert!(
                !force_preference_controller_hidden(
                    &mut dex,
                    "Lcom/lenovo/settings/privacy/UserExperienceSwitchController;",
                    "user_experience",
                    "mUserExperience",
                )
                .expect("second patch"),
                "the exact-original guard must refuse an already-patched body"
            );
        }
    }
    assert_eq!(hits, 1, "visibility rewrite should land in exactly one dex");
}

/// `force_invoke_const_bool` rewrites the real ZuiSettings
/// `LocaleListEditor` PRC gate. Set `DYNOBOX_ZUISETTINGS_DEX_DIR`.
#[test]
#[ignore = "fixture: set DYNOBOX_ZUISETTINGS_DEX_DIR"]
fn invoke_const_lands_on_real_zuisettings() {
    let dir = crate::test_fixtures::env("DYNOBOX_ZUISETTINGS_DEX_DIR");
    let dir = std::path::Path::new(&dir);
    let mut sites = 0usize;
    for name in [
        "classes.dex",
        "classes2.dex",
        "classes3.dex",
        "classes4.dex",
        "classes5.dex",
        "classes6.dex",
    ] {
        let Ok(mut dex) = std::fs::read(dir.join(name)) else {
            continue;
        };
        sites += force_invoke_const_bool(
            &mut dex,
            "Lcom/android/settings/localepicker/LocaleListEditor;",
            None,
            "Lcom/lenovo/common/utils/LenovoUtils;",
            "isPrcVersion",
            "Z",
            &[],
            false,
        )
        .expect("patch");
    }
    assert!(
        sites >= 1,
        "LocaleListEditor.isPrcVersion invoke sites should be rewritten"
    );
}

#[test]
fn invoke_const_int_rewrites_call_site_to_const() {
    // insns: [invoke-static {}, method@9 (3u)] [move-result v5 (1u)] = 8 bytes.
    let mut code = code_item_with_nops(4);
    code[16] = 0x71; // invoke-static
    code[18] = 0x09; // method idx 9
    code[22] = 0x0A; // move-result
    code[23] = 0x05; //   v5
    let n = rewrite_invoke_sites(&mut code, 0, 9, 0).unwrap();
    assert_eq!(n, 1);
    // const/16 v5, #0 + 2 nops
    assert_eq!(
        &code[16..24],
        &[0x13, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );

    // A value outside i16 range uses `const` (0x14) + 1 nop.
    let mut big = code_item_with_nops(4);
    big[16] = 0x71;
    big[18] = 0x09;
    big[22] = 0x0A;
    big[23] = 0x05;
    assert_eq!(
        rewrite_invoke_sites(&mut big, 0, 9, 0x0001_0000).unwrap(),
        1
    );
    assert_eq!(big[16], 0x14, "const vAA");
    assert_eq!(big[17], 0x05);
    assert_eq!(&big[18..22], &0x0001_0000i32.to_le_bytes());
    assert_eq!(&big[22..24], &[0x00, 0x00], "nop tail");

    // invoke-virtual (0x6e) is matched too, not just invoke-static.
    let mut virt = code_item_with_nops(4);
    virt[16] = 0x6e; // invoke-virtual
    virt[18] = 0x09;
    virt[22] = 0x0A;
    virt[23] = 0x05;
    assert_eq!(rewrite_invoke_sites(&mut virt, 0, 9, 1).unwrap(), 1);
    assert_eq!(&virt[16..20], &[0x13, 0x05, 0x01, 0x00], "const/16 v5, #1");
}

#[test]
fn invoke_const_site_index_rewrites_only_selected_call() {
    let mut code = code_item_with_nops(8);
    for (offset, register) in [(16usize, 1u8), (24usize, 2u8)] {
        code[offset] = 0x71;
        code[offset + 2] = 0x09;
        code[offset + 6] = 0x0A;
        code[offset + 7] = register;
    }
    let original_first = code[16..24].to_vec();
    let mut seen_sites = 0usize;

    let sites =
        rewrite_invoke_sites_filtered(&mut code, 0, 9, 0, Some(1), &mut seen_sites).unwrap();

    assert_eq!(sites, 1);
    assert_eq!(seen_sites, 2);
    assert_eq!(&code[16..24], original_first.as_slice());
    assert_eq!(
        &code[24..32],
        &[0x13, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
}

#[test]
fn nop_anchored_invoke_int_anchor_skips_non_target_nops_target() {
    // const vA, #0x7f12006d (6 bytes)
    let anchor = [0x14u8, 0x00, 0x6d, 0x00, 0x12, 0x7f];
    // invoke-direct {..}, method@5 (6 bytes) — not the target idx.
    let non_target = [0x70u8, 0x00, 0x05, 0x00, 0x00, 0x00];
    // invoke-interface {..}, method@7 (6 bytes) — the target idx.
    let target = [0x72u8, 0x00, 0x07, 0x00, 0x00, 0x00];
    let mut buf = Vec::new();
    buf.extend_from_slice(&anchor);
    buf.extend_from_slice(&non_target);
    buf.extend_from_slice(&target);
    let end = buf.len();

    let sites = rewrite_first_anchored_invoke(&mut buf, 0, end, 7, AnchorMatch::Int(0x7f12006d));

    assert_eq!(sites, 1);
    assert_eq!(&buf[0..6], &anchor, "anchor instruction untouched");
    assert_eq!(&buf[6..12], &non_target, "non-target invoke untouched");
    assert_eq!(&buf[12..18], &[0u8; 6], "target invoke nopped");
}

#[test]
fn nop_anchored_invoke_string_anchor_nops_target() {
    // const-string vA, string@42 (4 bytes)
    let anchor = [0x1au8, 0x00, 0x2a, 0x00];
    // invoke-virtual {..}, method@9 (6 bytes) — the target idx.
    let target = [0x6eu8, 0x00, 0x09, 0x00, 0x00, 0x00];
    let mut buf = Vec::new();
    buf.extend_from_slice(&anchor);
    buf.extend_from_slice(&target);
    let end = buf.len();

    let sites = rewrite_first_anchored_invoke(&mut buf, 0, end, 9, AnchorMatch::StringIdx(42));

    assert_eq!(sites, 1);
    assert_eq!(&buf[0..4], &anchor, "anchor instruction untouched");
    assert_eq!(&buf[4..10], &[0u8; 6], "target invoke nopped");
}

#[test]
fn nop_anchored_invoke_used_result_is_never_nopped() {
    // const/4 v0, #+5 (2 bytes)
    let anchor = [0x12u8, 0x50];
    // invoke-virtual {..}, method@3 (6 bytes) — the target idx.
    let target = [0x6eu8, 0x00, 0x03, 0x00, 0x00, 0x00];
    // move-result-object v0 (2 bytes) — consumes the invoke's result.
    let move_result = [0x0cu8, 0x00];
    let mut buf = Vec::new();
    buf.extend_from_slice(&anchor);
    buf.extend_from_slice(&target);
    buf.extend_from_slice(&move_result);
    let original = buf.clone();
    let end = buf.len();

    let sites = rewrite_first_anchored_invoke(&mut buf, 0, end, 3, AnchorMatch::Int(5));

    assert_eq!(sites, 0, "result is consumed, must not nop");
    assert_eq!(buf, original, "buffer left entirely untouched");
}

#[test]
fn nop_anchored_invoke_missing_anchor_is_noop() {
    // invoke-virtual {..}, method@3 (6 bytes) — matches target idx, but no
    // anchor ever arms the scan.
    let mut buf = vec![0x6eu8, 0x00, 0x03, 0x00, 0x00, 0x00];
    let original = buf.clone();
    let end = buf.len();

    let sites = rewrite_first_anchored_invoke(&mut buf, 0, end, 3, AnchorMatch::Int(999));

    assert_eq!(sites, 0, "anchor never present");
    assert_eq!(buf, original, "buffer left entirely untouched");
}

#[test]
fn nop_anchored_invoke_target_before_anchor_is_noop() {
    // invoke-virtual {..}, method@3 (6 bytes) — target idx, but appears
    // BEFORE the const/4 anchor that follows it.
    let target = [0x6eu8, 0x00, 0x03, 0x00, 0x00, 0x00];
    // const/4 v0, #+5 (2 bytes)
    let anchor = [0x12u8, 0x50];
    let mut buf = Vec::new();
    buf.extend_from_slice(&target);
    buf.extend_from_slice(&anchor);
    let original = buf.clone();
    let end = buf.len();

    let sites = rewrite_first_anchored_invoke(&mut buf, 0, end, 3, AnchorMatch::Int(5));

    assert_eq!(sites, 0, "invoke precedes the arm, must not be nopped");
    assert_eq!(buf, original, "buffer left entirely untouched");
}

/// `force_nop_anchored_invoke` lands on the real ZuiSecurity dexes.
/// Set DYNOBOX_ZUISECURITY_APK to the real ZuiSecurity.apk.
#[test]
#[ignore = "fixture: set DYNOBOX_ZUISECURITY_APK"]
fn nop_invoke_lands_on_real_zuisecurity() {
    let path = crate::test_fixtures::env("DYNOBOX_ZUISECURITY_APK");
    let apk = std::fs::read(path).expect("read ZuiSecurity.apk");
    let zip = crate::zip_util::parse_zip_central_directory(&apk).expect("parse apk");
    let (mut list_sites, mut update_sites) = (0usize, 0usize);
    for entry in zip.entries.iter().filter(|e| {
        e.name.ends_with(".dex")
            && e.compression_method == 0
            && !e.uses_data_descriptor
            && !e.is_zip64
            && e.data_start + e.compressed_size <= apk.len()
    }) {
        let mut dex = apk[entry.data_start..entry.data_start + entry.compressed_size].to_vec();
        list_sites += force_nop_anchored_invoke(
            &mut dex,
            "Lcom/zui/safecenter/ui/PhoneMainViewModel;",
            "<init>",
            "Ljava/util/List;",
            "add",
            "Z",
            &["Ljava/lang/Object;"],
            NopAnchor::Int(0x7f12003a),
        )
        .expect("list");
        update_sites += force_nop_anchored_invoke(
            &mut dex,
            "Lcom/lenovo/performance/autorun/services/AutoRunPkgReceiver;",
            "processAdd",
            "Lcom/lenovo/performance/autorun/AutoRunDataLayerManager;",
            "updateEntryIntoDb",
            "V",
            &["Lcom/lenovo/performance/autorun/AutoRunItem;"],
            NopAnchor::Str("InstallApp "),
        )
        .expect("update");
    }
    assert_eq!(list_sites, 1, "antivirus list item add nopped once");
    assert_eq!(update_sites, 1, "autorun update-preserve call nopped once");
}

// ---- force_view_gone -------------------------------------------------

// Instruction fragments for synthetic `findViewById` bindings:
// `const v0,id / invoke-virtual (findViewById) / move-result v0 /
// [check-cast / iput] / invoke-virtual {v0,p0} setOnClickListener`.
fn const_v0(id: u32) -> Vec<u8> {
    let b = id.to_le_bytes();
    vec![0x14, 0x00, b[0], b[1], b[2], b[3]]
}
fn findviewbyid() -> Vec<u8> {
    vec![0x6e, 0x20, 0x00, 0x00, 0x02, 0x00] // {p0, v0}, method@0
}
fn move_result_v0() -> Vec<u8> {
    vec![0x0c, 0x00]
}
fn check_cast_v0() -> Vec<u8> {
    vec![0x1f, 0x00, 0x00, 0x00]
}
fn iput_v0() -> Vec<u8> {
    vec![0x5b, 0x00, 0x00, 0x00]
}
fn set_on_click_v0() -> Vec<u8> {
    vec![0x6e, 0x20, 0x11, 0x11, 0x20, 0x00] // {v0,p0}, method@0x1111
}

#[test]
fn force_view_gone_hides_field_backed_anchor() {
    const ID_A: u32 = 0x7f0903f1;
    let mut buf = Vec::new();
    buf.extend(const_v0(ID_A));
    buf.extend(findviewbyid());
    buf.extend(move_result_v0());
    let tail = buf.len(); // 14
    buf.extend(check_cast_v0());
    buf.extend(iput_v0());
    buf.extend(set_on_click_v0());
    let end = buf.len(); // 28
    let head = buf[..tail].to_vec();

    let n = hide_views_in_method(&mut buf, 0, end, &[ID_A as i32], 1, 0x30);

    assert_eq!(n, 1);
    assert_eq!(&buf[..tail], &head[..], "view acquisition untouched");
    assert_eq!(
        &buf[tail..tail + 4],
        &[0x13, 0x01, 0x08, 0x00],
        "const/16 v1, #8 (GONE)"
    );
    assert_eq!(
        &buf[tail + 4..tail + 10],
        &[0x6e, 0x20, 0x30, 0x00, 0x10, 0x00],
        "invoke-virtual (v0,v1) setVisibility"
    );
    assert_eq!(&buf[tail + 10..end], &[0x00; 4], "nop pad");
}

#[test]
fn force_view_gone_swaps_click_only_after_anchor() {
    const ID_A: u32 = 0x7f0903f1;
    const ID_B: u32 = 0x7f0903d7;
    let mut buf = Vec::new();
    buf.extend(const_v0(ID_A));
    buf.extend(findviewbyid());
    buf.extend(move_result_v0());
    buf.extend(check_cast_v0());
    buf.extend(iput_v0());
    buf.extend(set_on_click_v0());
    buf.extend(const_v0(ID_B));
    buf.extend(findviewbyid());
    buf.extend(move_result_v0());
    let b_click = buf.len();
    buf.extend(set_on_click_v0());
    let end = buf.len();
    let b_head = buf[b_click - 14..b_click].to_vec();

    let n = hide_views_in_method(&mut buf, 0, end, &[ID_A as i32, ID_B as i32], 1, 0x30);

    assert_eq!(n, 2);
    assert_eq!(
        &buf[b_click..b_click + 6],
        &[0x6e, 0x20, 0x30, 0x00, 0x10, 0x00],
        "click-only view swapped to setVisibility (v0,v1)"
    );
    assert_eq!(
        &buf[b_click - 14..b_click],
        &b_head[..],
        "click-only view acquisition untouched"
    );
}

#[test]
fn force_view_gone_click_only_without_anchor_is_noop() {
    const ID_B: u32 = 0x7f0903d7;
    let mut buf = Vec::new();
    buf.extend(const_v0(ID_B));
    buf.extend(findviewbyid());
    buf.extend(move_result_v0());
    buf.extend(set_on_click_v0());
    let end = buf.len();
    let original = buf.clone();

    let n = hide_views_in_method(&mut buf, 0, end, &[ID_B as i32], 1, 0x30);

    assert_eq!(n, 0, "no field-backed anchor to establish scratch");
    assert_eq!(buf, original, "buffer untouched");
}

#[test]
fn force_view_gone_leaves_click_site_before_anchor() {
    const ID_A: u32 = 0x7f0903f1; // field-backed anchor, appears second
    const ID_B: u32 = 0x7f0903d7; // click-only, appears first
    let mut buf = Vec::new();
    buf.extend(const_v0(ID_B));
    buf.extend(findviewbyid());
    buf.extend(move_result_v0());
    let b_click = buf.len();
    buf.extend(set_on_click_v0());
    let b_click_bytes = buf[b_click..b_click + 6].to_vec();
    buf.extend(const_v0(ID_A));
    buf.extend(findviewbyid());
    buf.extend(move_result_v0());
    buf.extend(check_cast_v0());
    buf.extend(iput_v0());
    buf.extend(set_on_click_v0());
    let end = buf.len();

    let n = hide_views_in_method(&mut buf, 0, end, &[ID_A as i32, ID_B as i32], 1, 0x30);

    assert_eq!(n, 1, "only the anchor is hidden");
    assert_eq!(
        &buf[b_click..b_click + 6],
        &b_click_bytes[..],
        "click site before the anchor is not swapped"
    );
}

/// `force_view_gone` hides the ZuiSecurity nav entries on the real dex.
/// Set DYNOBOX_ZUISECURITY_APK to the real ZuiSecurity.apk.
#[test]
#[ignore = "fixture: set DYNOBOX_ZUISECURITY_APK"]
fn force_view_gone_lands_on_real_zuisecurity() {
    let path = crate::test_fixtures::env("DYNOBOX_ZUISECURITY_APK");
    let apk = std::fs::read(path).expect("read ZuiSecurity.apk");
    let zip = crate::zip_util::parse_zip_central_directory(&apk).expect("parse apk");
    let mut hidden = 0usize;
    for entry in zip.entries.iter().filter(|e| {
        e.name.ends_with(".dex")
            && e.compression_method == 0
            && !e.uses_data_descriptor
            && !e.is_zip64
            && e.data_start + e.compressed_size <= apk.len()
    }) {
        let mut dex = apk[entry.data_start..entry.data_start + entry.compressed_size].to_vec();
        hidden += force_view_gone(
            &mut dex,
            "Lcom/zui/safecenter/ui/MainNavigationActivity;",
            "initView",
            &[0x7f0903fe, 0x7f090413],
            1,
        )
        .expect("hide");
    }
    assert_eq!(hidden, 2, "permission + antivirus nav entries hidden");
}

/// `invoke_const_bool` forces `isRowVersion()` at the single call site in
/// `AppPermissionPreferenceController` on the real ZuiSettings.apk, so the
/// app-permission screen routes to the AOSP page. Set DYNOBOX_ZUISETTINGS_APK.
#[test]
#[ignore = "fixture: set DYNOBOX_ZUISETTINGS_APK"]
fn isrowversion_forced_in_permission_controller_on_real_zuisettings() {
    let path = crate::test_fixtures::env("DYNOBOX_ZUISETTINGS_APK");
    let apk = std::fs::read(path).expect("read ZuiSettings.apk");
    let zip = crate::zip_util::parse_zip_central_directory(&apk).expect("parse apk");
    let mut sites = 0usize;
    for entry in zip.entries.iter().filter(|e| {
        e.name.ends_with(".dex")
            && e.compression_method == 0
            && !e.uses_data_descriptor
            && !e.is_zip64
            && e.data_start + e.compressed_size <= apk.len()
    }) {
        let mut dex = apk[entry.data_start..entry.data_start + entry.compressed_size].to_vec();
        sites += force_invoke_const_bool(
            &mut dex,
            "Lcom/android/settings/applications/appinfo/AppPermissionPreferenceController;",
            None,
            "Lcom/lenovo/common/utils/LenovoUtils;",
            "isRowVersion",
            "Z",
            &[],
            true,
        )
        .expect("patch");
    }
    assert_eq!(
        sites, 1,
        "isRowVersion forced at exactly one controller site"
    );
}

// ---- force_remoteviews_gone ------------------------------------------

fn const_id(id: u32) -> Vec<u8> {
    let b = id.to_le_bytes();
    vec![0x14, 0x00, b[0], b[1], b[2], b[3]] // const v0, #id
}

#[test]
fn remoteviews_gone_rewrites_setup_site() {
    const ID: u32 = 0x7f09009e;
    let mut buf = const_id(ID);
    buf.extend([0x62, 0x01, 0x00, 0x00]); // sget-object v1, field@0 (2-unit arg load)
    buf.extend([0x71, 0x40, 0x11, 0x11, 0x08, 0x01]); // invoke-static {..} (3 units)
    let end = buf.len();
    let head = buf[..6].to_vec();

    let ok = rewrite_remoteviews_gone(&mut buf, 0, end, ID as i32, 8, 1, 0x30);

    assert!(ok);
    assert_eq!(&buf[..6], &head[..], "const id load untouched");
    assert_eq!(
        &buf[6..10],
        &[0x13, 0x01, 0x08, 0x00],
        "const/16 v1, #8 (GONE)"
    );
    assert_eq!(
        &buf[10..16],
        &[0x6e, 0x30, 0x30, 0x00, 0x08, 0x01],
        "invoke-virtual setViewVisibility (v8,v0,v1)"
    );
}

#[test]
fn remoteviews_gone_skips_mismatched_shape() {
    const ID: u32 = 0x7f09009e;
    // const vId, ID followed directly by a 3-unit invoke (no 2-unit load).
    let mut buf = const_id(ID);
    buf.extend([0x71, 0x30, 0x11, 0x11, 0x08, 0x00]); // invoke at pc+6 (width 3, not 2)
    buf.extend([0x71, 0x30, 0x11, 0x11, 0x08, 0x00]);
    let end = buf.len();
    let original = buf.clone();

    let ok = rewrite_remoteviews_gone(&mut buf, 0, end, ID as i32, 8, 1, 0x30);

    assert!(!ok, "wrong shape must not be rewritten");
    assert_eq!(buf, original, "buffer untouched");
}

/// `force_method_return_void` neutralizes the antivirus engine init on the
/// real ZuiSecurity.apk. Set DYNOBOX_ZUISECURITY_APK.
#[test]
#[ignore = "fixture: set DYNOBOX_ZUISECURITY_APK"]
fn method_nop_lands_on_real_zuisecurity_antivirus() {
    let path = crate::test_fixtures::env("DYNOBOX_ZUISECURITY_APK");
    let apk = std::fs::read(path).expect("read ZuiSecurity.apk");
    let zip = crate::zip_util::parse_zip_central_directory(&apk).expect("parse apk");
    let mut hits = 0usize;
    for entry in zip.entries.iter().filter(|e| {
        e.name.ends_with(".dex")
            && e.compression_method == 0
            && !e.uses_data_descriptor
            && !e.is_zip64
            && e.data_start + e.compressed_size <= apk.len()
    }) {
        let mut dex = apk[entry.data_start..entry.data_start + entry.compressed_size].to_vec();
        let cls = "Lcom/lenovo/safecenter/antivirus/external/AntiVirusInterface;";
        if force_method_return_void(
            &mut dex,
            cls,
            "initTMSApplication",
            "V",
            &["Landroid/content/Context;", "Z"],
        )
        .expect("nop")
        {
            hits += 1;
        }
        let mut dex_modified = false;
        for m in [
            "startAutoScanBroadcastReceiver",
            "startUpdateTMSVirusDbReceiver",
        ] {
            if force_method_return_void(&mut dex, cls, m, "V", &["Landroid/content/Context;"])
                .expect("nop")
            {
                hits += 1;
                dex_modified = true;
            }
        }
        // Optionally emit the finalized dex (sums recomputed, as dbp does) so a
        // structural validator (dexdump / dex2oat) can confirm it still loads.
        if let Ok(out) = std::env::var("DYNOBOX_ZUISECURITY_DEX_OUT") {
            if dex_modified {
                crate::dex_util::recompute_dex_header_sums(&mut dex);
                std::fs::write(std::path::Path::new(&out).join(&entry.name), &dex)
                    .expect("write patched dex");
            }
        }
    }
    assert_eq!(
        hits, 3,
        "all 3 AntiVirusInterface hub methods neutralized once"
    );
}

/// A one-entry zip whose entry is deflated with no compression, so a
/// compressible rewrite leaves plenty of slack to absorb.
fn zip_with_uncompressed_deflate(name: &str, data: &[u8]) -> Vec<u8> {
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::none());
    enc.write_all(data).unwrap();
    let packed = enc.finish().unwrap();
    let crc = crc32_ieee(data);
    let header = |sig: u32, central: bool| {
        let mut h = sig.to_le_bytes().to_vec();
        if central {
            h.extend_from_slice(&20u16.to_le_bytes());
        }
        for v in [20u16, 0, 8, 0, 0] {
            h.extend_from_slice(&v.to_le_bytes());
        }
        for v in [crc, packed.len() as u32, data.len() as u32] {
            h.extend_from_slice(&v.to_le_bytes());
        }
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        if central {
            // Comment, disk, internal/external attributes, local offset.
            h.extend_from_slice(&[0; 10]);
            h.extend_from_slice(&0u32.to_le_bytes());
        }
        h.extend_from_slice(name.as_bytes());
        h
    };
    let mut zip = header(0x04034b50, false);
    zip.extend_from_slice(&packed);
    let cd_offset = zip.len() as u32;
    let central = header(0x02014b50, true);
    zip.extend_from_slice(&central);
    zip.extend_from_slice(&0x06054b50u32.to_le_bytes());
    for v in [0u16, 0, 1, 1] {
        zip.extend_from_slice(&v.to_le_bytes());
    }
    zip.extend_from_slice(&(central.len() as u32).to_le_bytes());
    zip.extend_from_slice(&cd_offset.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip
}

fn read_entry(zip_bytes: &[u8], name: &str) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).unwrap();
    let mut entry = archive.by_name(name).unwrap();
    let mut out = Vec::new();
    entry.read_to_end(&mut out).unwrap();
    out
}

#[test]
fn absorb_slack_spills_past_the_extra_field_into_empty_blocks() {
    let (payload, pad) = absorb_slack(vec![1, 2, 3], 10, 100).unwrap();
    assert_eq!((payload, pad), (vec![1, 2, 3], 7));

    let (payload, pad) = absorb_slack(vec![1, 2, 3], 20, 4).unwrap();
    assert_eq!(payload.len() + pad, 20);
    assert!(pad <= 4);
    assert!(payload.ends_with(&[1, 2, 3]));
    assert!(
        payload[..payload.len() - 3]
            .chunks(5)
            .all(|b| b == EMPTY_STORED_BLOCK)
    );
}

#[test]
fn rewrite_recompresses_a_deflated_entry_in_place() {
    let original: Vec<u8> = (0..4096u32).flat_map(|i| (i % 251).to_le_bytes()).collect();
    let mut zip_bytes = zip_with_uncompressed_deflate("classes.dex", &original);
    let len = zip_bytes.len();
    let mut patched = original.clone();
    patched[100] ^= 0xff;

    let layout = parse_zip_central_directory(&zip_bytes).unwrap();
    let rewrite = EntryRewrite {
        entry_idx: 0,
        inflated: patched.clone(),
        was_deflated: true,
        descriptor: None,
    };
    assert!(commit_entry_rewrites(&mut zip_bytes, &layout, vec![rewrite]).unwrap());
    assert_eq!(zip_bytes.len(), len);
    assert_eq!(read_entry(&zip_bytes, "classes.dex"), patched);
}

#[test]
fn rewrite_uses_empty_blocks_when_slack_exceeds_the_extra_field() {
    // 256 KiB of zeros stored uncompressed recompresses to a few hundred
    // bytes: far more slack than a u16 extra field can hold.
    let original = vec![0u8; 256 << 10];
    let mut zip_bytes = zip_with_uncompressed_deflate("classes.dex", &original);
    let len = zip_bytes.len();
    let mut patched = original.clone();
    patched[7] = 1;

    let layout = parse_zip_central_directory(&zip_bytes).unwrap();
    let rewrite = EntryRewrite {
        entry_idx: 0,
        inflated: patched.clone(),
        was_deflated: true,
        descriptor: None,
    };
    assert!(commit_entry_rewrites(&mut zip_bytes, &layout, vec![rewrite]).unwrap());
    assert_eq!(zip_bytes.len(), len);
    assert_eq!(read_entry(&zip_bytes, "classes.dex"), patched);
    let entry = &layout.entries[0];
    let extra_len = read_u16_at(&zip_bytes, entry.local_header_offset + 28).unwrap();
    assert!(extra_len > 60_000);
}
