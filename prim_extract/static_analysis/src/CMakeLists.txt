add_executable(prim_anal_sa prim_anal_sa.cpp)
target_link_libraries(prim_anal_sa PRIVATE ${llvm_libs} ${SVF_LIB})

add_executable(prim_anal_spaf prim_anal_spaf.cpp)
target_link_libraries(prim_anal_spaf PRIVATE ${llvm_libs} ${SVF_LIB})
