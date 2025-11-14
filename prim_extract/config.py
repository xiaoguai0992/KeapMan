import os

class Config:
    workspace_root_dir = os.getenv("WORKSPACE_ROOT_DIR")
    dataset_root_dir = os.getenv("DATASET_ROOT_DIR")
    svf_root_dir = os.getenv("SVF_ROOT_DIR")
    objmeasure_root_dir = os.getenv("OBJMEASURE_ROOT_DIR")
    case_id = 'pipe_buffer'
    dataset_dir = os.path.join(dataset_root_dir, case_id)
    workspace_dir = os.path.join(workspace_root_dir, case_id)

    linux_src_dir = os.getenv("KERNEL_DIR")
    linux_build_dir = os.getenv("KERNEL_DIR")
    fsimage_dir = os.getenv("IMAGE_PATH")

    prim_sa_bin = 'static_analysis/build/bin/prim_anal_sa'
    prim_spaf_bin = 'static_analysis/build/bin/prim_anal_spaf'
    alloccheck_py = os.getenv("PY_ALLOCCHECK")
    freecheck_py = os.getenv("PY_FREECHECK")
    linux_bc_dir = os.getenv("LINUX_BC_DIR")
    svf_dir = os.getenv("SVF_ROOT_DIR") 

