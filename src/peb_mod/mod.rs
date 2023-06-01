use core::arch::asm;
use byteorder::{LittleEndian, ByteOrder};
use winapi::shared::minwindef::PULONG;
use std::ptr;
use std::mem;
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_DATA_DIRECTORY};
use windows_sys::Win32::System::Kernel::LIST_ENTRY;
mod types;
use std::io::{self, Read};
use std::str;
// Getting process pid and Handle
use std::process;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::memoryapi::VirtualProtect;
use std::os::raw::c_void;


// typedef
type HANDLE = *mut c_void;

// Constants
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

pub struct MemWalker {
    pub name: String,
    pub module_base: *const u64,
    pub gambit_base: *mut u64,
    pub module_size: usize,
    pub gambit_size: usize
}

pub struct peb {
    pub ptr: *const usize, // Rolling with usize, so arch determines size of pointer
    pub ldr_ptr: *const u64,
    pub ldr_inmem_order_flink: *const u64
}

#[inline]
pub unsafe fn __readgsqword(offset: types::DWORD) -> usize {
    let out: usize;
    asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    out
}


impl MemWalker {

    pub fn walk(&mut self, target_module_name: &str) -> &mut MemWalker {

        let mut peb = peb {
            ptr: ptr::null(),
            ldr_ptr: ptr::null(),
            ldr_inmem_order_flink: ptr::null()
        };

        unsafe {
            if is_wow64() { // Check if arch x64
                peb.ptr = __readgsqword(0x60)  as *const usize;
                println!("PEB OFFSET: {:?}", peb.ptr);
            }

            let peb_slice = std::slice::from_raw_parts(
                peb.ptr, 
                4
            );
            peb.ldr_ptr = *(&peb_slice[3]) as *const u64;
            println!("PEB LDR: {:?}", peb.ldr_ptr as *const u64);

            let peb_ldr_slice = std::slice::from_raw_parts(
                peb.ldr_ptr,
                5
            );

            peb.ldr_inmem_order_flink = *(&peb_ldr_slice[4]) as *const u64;

            loop {  // Loop through LDR Table until we find target DLL string

                println!("PEB LDR INLOADORDER FLINK Slice: {:?}", peb.ldr_inmem_order_flink);

                let ldr_entry_buffer = std::slice::from_raw_parts(
                    peb.ldr_inmem_order_flink,
                    11
                );

                self.module_base = *(&ldr_entry_buffer[4]) as *const u64;
                let dll_string_ptr = *(&ldr_entry_buffer[10]) as *const u16; // PTR to dll utf-16 name string

                if self.findModuleString("gambit_client.exe", dll_string_ptr) {
                    println!("Woo! Found gambit base: {:?}", self.module_base);
                    self.gambit_base = self.module_base as *mut u64;
                    self.gambit_size = ldr_entry_buffer[6] as usize;
                    println!("Gambit Size: {:?}", self.gambit_size);
                }
                else if self.findModuleString(target_module_name, dll_string_ptr) {
                    println!("Woo! Found target module base: {:?}", self.module_base);
                    self.module_base = self.module_base as *mut u64;
                    self.module_size = ldr_entry_buffer[6] as usize;
                    println!("Module Size: {:?}", self.module_size);

                    self.pe_walk();
                    return self;
                    //break;
                }
                    
                peb.ldr_inmem_order_flink = *(&ldr_entry_buffer[0]) as *const u64;  // set Flink to next module

            }

        }
    }

    // Finds UTF-16 module string for target module
    pub unsafe fn findModuleString(&mut self, target_module_name: &str, dll_string_ptr: *const u16) -> bool {

        let mut token = false;
        // Get DLL String Name Size in u16 as it's stored as UTF-16 string in mem
        let dll_name_16: Vec<u16> = target_module_name.encode_utf16().collect();
        println!("Target Module String Name Size: {:?}", mem::size_of_val(&dll_name_16));

        let dll_string_buffer = std::slice::from_raw_parts(
            dll_string_ptr,
            mem::size_of_val(target_module_name) + 1
        );
    
        // Trim the null bytes off of String output
        let mut dll_string_name = String::from_utf16_lossy(dll_string_buffer);
        dll_string_name = String::from(dll_string_name.trim_matches(char::from(0)));
        println!("DLL String Name: {}", dll_string_name);

        if dll_string_name == target_module_name {
            token = true;
            self.module_base = self.module_base as *mut u64;
        }

        return token;
    }


    pub fn pe_walk(&mut self) {

        unsafe {

            /** Initial PE Walk **/
            let dos_header_slice = std::slice::from_raw_parts(
                self.module_base as *const u8, 
                0x3d
            );

            let pe_offset =  (*(&dos_header_slice[0x3c]) as *const u64) as usize;   // e_lfanew
            println!("PE Offset: {:?}", pe_offset as usize / 8);

            let pe_header_slice = std::slice::from_raw_parts(
                self.module_base as *const u8,
                pe_offset + 1
            );
            println!("PE Header Initial Value: {:?}", *(&pe_header_slice[pe_offset]) as *const u64);

            let pe_header = (self.module_base as usize + pe_offset) as *const u64;
            println!("PE Header: {:?}", pe_header);

            let IMAGE_NT_SIGNATURE = *(pe_header as *const u32) as *const u32;
            println!("IMAGE NT SIGNATURE: {:?}", IMAGE_NT_SIGNATURE);

            let NTDLL_IMAGE_BASE = std::slice::from_raw_parts(pe_header as *const u64, self.module_size)[6] as *const u64;
            println!("IMAGE BASE: {:?}", NTDLL_IMAGE_BASE);
            
            /** Export Directory **/
            let export_dir_chunk = std::slice::from_raw_parts(pe_header as *const u32, self.module_size);
            let export_dir_offset = export_dir_chunk[34] as *const u64; // 0x70 from Options Header
            let export_dir_size = export_dir_chunk[35] as usize; // 0x74
            let export_dir_entry_ptr = &(std::slice::from_raw_parts((NTDLL_IMAGE_BASE as usize + export_dir_offset as usize) as *const u64, export_dir_size))[0] as *const u64; // RVA
            println!("Export Dir Entry PTR: {:?}", export_dir_entry_ptr);
            let export_dir_slice = std::slice::from_raw_parts(export_dir_entry_ptr as *const u32, export_dir_size);
            // Functions
            let export_dir_functions_count = export_dir_slice[5] as *const u64;
            let export_dir_functions_RVA = export_dir_slice[7] as *const u64;
            let export_dir_functions_ptr: *const u64 = ((NTDLL_IMAGE_BASE as usize + export_dir_functions_RVA as usize) as *const u32) as *const u64;
            // Function Names
            let export_dir_names_count = export_dir_slice[6] as *const u64;
            let export_dir_names_RVA = export_dir_slice[8] as *const u64;
            let export_dir_names_ptr: *const u64 = ((NTDLL_IMAGE_BASE as usize + export_dir_names_RVA as usize) as *const u32) as *const u64;

            // Walking the Export Dir Functions
            let mut function_offset: usize = 0;
            let mut name_offset: usize = 0;
            for i in 0..(export_dir_functions_count as u32) {

                let mut function_RVA: *const u32 = std::ptr::null();
                let mut name_RVA: *const u32 = std::ptr::null(); // Will not be incremented until iter 1 due to ntdll having blank name RVA for init

                // TODO:: Implement alternative loop for non-ntdll modules

                if i==0 {
                    function_RVA = *((export_dir_functions_ptr as usize) as *const u32) as *const u32;
                    function_offset = function_offset +  std::mem::size_of::<u32>();
                }
                else if i==1 {  // Due to first function RVA not haviung an associated name, this skip is necessary for this flow
                    function_RVA = *((export_dir_functions_ptr as usize + function_offset) as *const u32) as *const u32;
                    name_RVA = *((export_dir_names_ptr as usize) as *const u32) as *const u32;
                    function_offset = function_offset +  std::mem::size_of::<u32>();
                    name_offset = name_offset + std::mem::size_of::<u32>();
                }
                else {
                    function_RVA = *((export_dir_functions_ptr as usize + function_offset) as *const u32) as *const u32;
                    name_RVA = *((export_dir_names_ptr as usize + name_offset) as *const u32) as *const u32;
                    function_offset = function_offset +  std::mem::size_of::<u32>();
                    name_offset = name_offset + std::mem::size_of::<u32>();
                }
                
                /* If target function is found */
                if self.RVA(String::from("NtProtectVirtualMemory"), NTDLL_IMAGE_BASE, export_dir_names_count, name_RVA, function_RVA) {
                    break;
                }
            }

        } // End of Unsafe Scope
    }

    // Dereference Function and Name RVA's
    pub fn RVA(&mut self, function_target: String, NTDLL_IMAGE_BASE: *const u64, names_count: *const u64, name_RVA: *const u32, function_RVA: *const u32) -> bool {

        unsafe {
            let mut offset: usize = 0;
            let mut name: Vec<char> = Vec::new();
            let name_data = &*((NTDLL_IMAGE_BASE as usize + name_RVA as usize) as *const u8) as *const u8;
            println!("NAME DATA PTR {:?}", name_data);

            if name_RVA as usize != 0x0 {   // Filter out no names

                for i in 0..(names_count as u32) {

                    let name_char = *((name_data as usize + offset as usize) as *const u8) as *const u8;
                    
                    if name_char as usize == 0x00 { // break if we reach end of name ASCII string
                        let fullname:String = String::from_iter(name.clone());

                        if fullname == function_target {    // If function is our target function
                            println!("Function Name: {}", fullname);
                            let function_data_ptr = &*((NTDLL_IMAGE_BASE as usize + function_RVA as usize) as *const u64) as *const u64;
                            println!("Function Data PTR: {:?}", function_data_ptr);
                            let syscall_id = self.extract_syscall(function_data_ptr); // Extract syscall ID from function asm
                            let processHandle: HANDLE = GetCurrentProcess();
                            let mut oldProtect: u32 = 9;
                            let size = 0x3c as usize;
                            //thread::sleep_ms(8000);
                            VirtualProtect(self.gambit_base as *mut c_void, size, PAGE_EXECUTE_READWRITE, &mut oldProtect);
                            syscaller(processHandle, &self.gambit_base, &size, PAGE_EXECUTE_READWRITE, &mut oldProtect, syscall_id);
                            println!("PTR: {:?}", self.gambit_base);
                            println!("Did Syscall!");
                            println!("Value of oldProt: {:?}", oldProtect);
                            //thread::sleep_ms(8000);

                            return true;
                        }

                        break;
                    }
                    
                    name.push((name_char as u8) as char);

                    offset = offset +  std::mem::size_of::<u8>();

                }
            }
        }
        return false;
    }


    fn extract_syscall(&mut self, function_ptr: *const u64) -> *const u8 {

        let egg = [0x4c, 0x8b, 0xd1, 0xb8]; // Syscall identifer asm chunk

        unsafe {

            let func_slice = std::slice::from_raw_parts(function_ptr as *const u8, 6); 
            let window_val = func_slice.windows(4).position(|x| *x == egg);
            if window_val.is_some() {
                println!("Woo! Found our syscall ID");
                let syscall_id: *const u8 = func_slice[4] as *const u8;
                println!("SYSCALL ID: {:?}", syscall_id);

                return syscall_id;
            }

        }

        return std::ptr::null();

    }

    pub fn init() -> Self {
        let mut memwalker = MemWalker {
            name: String::from("ntdll.dll"),
            module_base: ptr::null(),
            gambit_base: 0 as *mut u64,
            module_size: 0,
            gambit_size: 0
        };

        return memwalker;
    }


}


// Syscall Assembly
pub unsafe extern "system" fn syscaller(handle: HANDLE, image_base: &*mut u64, size: &usize, newProtect: u32, oldProtect: &u32, syscall_id: *const u8) {

    asm!(
        "mov rsi, [rsp + 0x50]",
        "lea rsi,  [rsp + 0x38]",
        "lea rdi,  [rsp + 0x28]",
        "mov rbp, r8",
        "mov r12, rsp",
        "mov rsp, rdi",
        "mov r10, rcx",
        "mov eax, {0:e}",
        "syscall",
        "mov rsp, r12",
        in(reg) syscall_id
    );

}

/// Checks to see if the architecture x86 or x86_64
pub fn is_wow64() -> bool {
    // A usize is 4 bytes on 32 bit and 8 bytes on 64 bit
    if std::mem::size_of::<usize>() == 4 {
        return false;
    }

    return true;
}