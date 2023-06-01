use crate::peb_mod::{MemWalker,is_wow64};

pub fn syscallInit() {

    if is_wow64() {
        let mut memWorker = MemWalker::init();
        let data = memWorker.walk("ntdll.dll");
    }
    
}

