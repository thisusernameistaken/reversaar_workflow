from binaryninja import (
    Workflow,
    Activity,
    MediumLevelILConstPtr,
    Transform,
    Type,
    MediumLevelILOperation,
    ExpressionIndex,
    SegmentFlag,
    SectionSemantics,

)
import json

xor_func_address = 0x2aa0
def xor_dec(analysis_context):
    current_function = analysis_context.function
    bv = current_function.view
    for ref in current_function.call_sites:
        call_func = ref.mlil.dest
        if isinstance(call_func,MediumLevelILConstPtr) and call_func.constant == xor_func_address:
            p1 = ref.mlil.params[0].constant
            p2 = ref.mlil.params[1].constant
            size = ref.mlil.params[2].constant
            
            p1_value = bv.read(p1,size)
            p2_value = bv.read(p2,size)
            xor_value = Transform['XOR'].encode(p1_value,{"key":p2_value})
            
            sec_beginning = bv.get_section_by_name(".synthetic_builtins").end
            dec_size = bv.end - sec_beginning
            xor_addr = bv.end
            sec_data = bv.read(sec_beginning,dec_size)
            sec_data += xor_value + b"\x00"
            dec_section = bv.get_section_by_name(".decrypted_strings")
            if dec_section is not None:
                bv.remove_auto_section(".decrypted_strings")
                bv.memory_map.remove_memory_region("dec_strings")
            bv.memory_map.add_memory_region("dec_strings",sec_beginning,sec_data,SegmentFlag.SegmentContainsData|SegmentFlag.SegmentReadable)
            bv.add_auto_section(".decrypted_strings",sec_beginning,len(sec_data),SectionSemantics.ReadOnlyDataSectionSemantics)

            bv.define_data_var(xor_addr,Type.array(Type.char(),len(xor_value)+1))

            mlil_expr_id = current_function.get_llil_at(ref.address).mlil.expr_index
            mlil_var_dest = current_function.mlil.get_expr(mlil_expr_id).operands[0][0].identifier
            replaced_il = current_function.mlil.get_expr(mlil_expr_id)
            mlil_const_ptr = current_function.mlil.expr(MediumLevelILOperation.MLIL_SET_VAR,mlil_var_dest,current_function.mlil.expr(MediumLevelILOperation.MLIL_CONST_PTR, ExpressionIndex(xor_addr),size=8),size=8)
            current_function.mlil.replace_expr(replaced_il,mlil_const_ptr)

    current_function.mlil.generate_ssa_form()


configuration = json.dumps({
    "name": "analysis.plugins.RevsaarXOR",
    "title": "XOR String Decoder",
    "description": "decrypt the xor",
    "eligibility": {
        "auto": {
            "default": True
        }
    }
})


xor_wf = Workflow().clone("RevsaarXORWorkflow")
xor_wf.register_activity(Activity(configuration,action=xor_dec))
xor_wf.insert('core.function.analyzeConditionalNoReturns',['analysis.plugins.RevsaarXOR'])

xor_wf.register()