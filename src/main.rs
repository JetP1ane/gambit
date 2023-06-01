mod peb_mod;
mod syscall;

use syscall::syscallInit;

use crate::peb_mod::MemWalker;


fn main() {
    
    syscallInit();

    loop {
        
    }

}