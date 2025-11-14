import os

class Config:
    workspace_root_dir = os.getenv("WORKSPACE_ROOT_DIR")
    dataset_root_dir = os.getenv("DATASET_ROOT_DIR")
    svf_root_dir = os.getenv("SVF_ROOT_DIR")
    objmeasure_root_dir = os.getenv("OBJMEASURE_ROOT_DIR")
    case_id = 'pipe_buffer'
    # case_id = 'tty_struct'
    # case_id = 'user_key_payload'
    # case_id = 'drm_property_blob'
    # case_id = 'msg_msg'
    # case_id = 'packet_sock'
    # case_id = 'tty_file_private'
    # case_id = 'timerfd_ctx'
    # case_id = 'key'
    # case_id = 'seq_file'
    # case_id = 'urb'
    # case_id = 'per_cpu_ref_data'
    # case_id = 'pgv'
    # case_id = 'shm_file_data'
    # case_id = 'kioctx_table'
    # case_id = 'xfrm_sec_ctx'
    dataset_dir = os.path.join(dataset_root_dir, case_id)
    workspace_dir = os.path.join(workspace_root_dir, case_id)

    linux_src_dir = os.getenv("KERNEL_DIR")
    linux_build_dir = os.getenv("KERNEL_DIR")
    fsimage_dir = os.getenv("IMAGE_PATH")

    # alloc_finder_bin = 'static_analysis/build/bin/alloc_finder'
    # free_finder_bin = 'static_analysis/build/bin/free_finder'
    prim_sa_bin = 'static_analysis/build/bin/prim_anal_sa'
    prim_spaf_bin = 'static_analysis/build/bin/prim_anal_spaf'
    alloccheck_py = os.getenv("PY_ALLOCCHECK")
    freecheck_py = os.getenv("PY_FREECHECK")
    linux_bc_dir = os.getenv("LINUX_BC_DIR")
    svf_dir = os.getenv("SVF_ROOT_DIR") 
    # wpa_bin = os.path.join(svf_dir, 'RelWithDebInfo-build/bin/wpa')

