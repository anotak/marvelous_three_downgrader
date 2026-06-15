
use digest_io::HashReader;
use sha2::{Sha256, Digest};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::fmt::Display;

const SHA256_OLD_UMVC3_EXE : &[u8] = b"b2f2fabe01949f1130f1cc42d31709a2a8cbed9c524330b5fdee71583bd21e7e";
const SHA256_OLD_STEAM_API64_DLL : &[u8] = b"71af8666392acad2080a816b9f1196fe9ccb950e1db8a549f8312c4d231f55a8";

#[expect(unused)]
const FILESIZE_OLD_UMVC3_EXE : usize = 14828952;
#[expect(unused)]
const FILESIZE_OLD_STEAM_API64_DLL : usize = 235600;

const SHA256_NEW_UMVC3_EXE : &[u8] = b"1593ceddedb21ed5f82deed8e38cb95113eee25a59dff1c5a22f3015870bb977";
const SHA256_NEW_STEAM_API64_DLL : &[u8] = b"eb17909a76668cf9ae0b92a618a34a50f6c73d3a6787cb4dd8ce36a8b10bfb75";

#[expect(unused)]
const FILESIZE_NEW_UMVC3_EXE : usize = 13953512;
#[expect(unused)]
const FILESIZE_NEW_STEAM_API64_DLL : usize = 317080;

const UMVC3_DIFF : &[u8] = include_bytes!("../data/umvc3.exe.diffed");
const STEAM_API64_DIFF : &[u8] = include_bytes!("../data/steam_api64.dll.diffed");

fn array_of_bytes_to_text(bytes : &[u8]) -> Vec<u8> {
    let mut text = Vec::with_capacity(bytes.len() * 2);
    
    for byte in bytes
    {
        let characters = format!("{byte:02x}");
        let characters = characters.as_bytes();
        
        for c in characters {
            text.push(*c);
        }
    }
    
    text
}

fn get_filesize<T: AsRef<Path>>(path : T) -> Result<usize, Box<dyn std::error::Error>>
{
    let filesize = {
        let metadata = std::fs::metadata(path)?;
        
        metadata.len() as usize
    };
    
    Ok(filesize)
}


type Hashed = Vec<u8>;
type FileBytes = Vec<u8>;

fn get_hash<T: AsRef<Path>>(path : T) -> Result<(FileBytes, Hashed), Box<dyn std::error::Error>>
{
    let filesize = get_filesize(&path)?;
    
    println!("{filesize} filesize");
    
    let f = File::open(path)?;
    let mut reader = HashReader::<Sha256, File>::new(f);

    let mut buf = Vec::with_capacity(filesize);
    reader.read_to_end(&mut buf)?;

    let hash = reader.finalize().to_vec();
    
    Ok((buf, hash))
}

fn main()  -> Result<(), Box<dyn std::error::Error>> {
    println!("Checking exe version!");
    
    create_diff(
        r"C:\Program Files (x86)\Steam\steamapps\common\ULTIMATE MARVEL VS. CAPCOM 3\old_version_exe\umvc3.exe",
        r"C:\Program Files (x86)\Steam\steamapps\common\ULTIMATE MARVEL VS. CAPCOM 3\umvc3.exe",
        r"C:\Program Files (x86)\Steam\steamapps\common\ULTIMATE MARVEL VS. CAPCOM 3\old_version_exe\umvc3.exe.diffed"
        )?;
    
    create_diff(
        r"C:\Program Files (x86)\Steam\steamapps\common\ULTIMATE MARVEL VS. CAPCOM 3\old_version_exe\steam_api64.dll",
        r"C:\Program Files (x86)\Steam\steamapps\common\ULTIMATE MARVEL VS. CAPCOM 3\steam_api64.dll",
        r"C:\Program Files (x86)\Steam\steamapps\common\ULTIMATE MARVEL VS. CAPCOM 3\old_version_exe\steam_api64.dll.diffed"
        )?;
    
    {
        let (buf, hash) = get_hash(r"C:\Program Files (x86)\Steam\steamapps\common\ULTIMATE MARVEL VS. CAPCOM 3\umvc3.exe")?;
        
        let hash : &[u8] = hash.as_slice();
        let hash = array_of_bytes_to_text(hash);
        
        match hash.as_slice() {
            SHA256_OLD_UMVC3_EXE => {
                println!("Old umvc3 exe hash, no change needed");
            },
            SHA256_NEW_UMVC3_EXE => {
                println!("New umvc3 exe hash");
                
                revert(
                    buf,
                    r"C:\Program Files (x86)\Steam\steamapps\common\ULTIMATE MARVEL VS. CAPCOM 3\old_version_exe\umvc3.exe.test",
                    UMVC3_DIFF,
                    SHA256_OLD_UMVC3_EXE
                    )?;
                
            },
            _ => {
                println!("Unidentified umvc3 exe??");
            }
        }
    }
    
    {
        let (buf, hash) = get_hash(r"C:\Program Files (x86)\Steam\steamapps\common\ULTIMATE MARVEL VS. CAPCOM 3\steam_api64.dll")?;
        
        let hash : &[u8] = hash.as_slice();
        let hash = array_of_bytes_to_text(hash);
        
        match hash.as_slice() {
            SHA256_OLD_STEAM_API64_DLL => {
                println!("Old steam_api.dll hash, no change needed");
            },
            SHA256_NEW_STEAM_API64_DLL => {
                println!("New steam_api.dll hash");
                
                revert(
                    buf,
                    r"C:\Program Files (x86)\Steam\steamapps\common\ULTIMATE MARVEL VS. CAPCOM 3\old_version_exe\steam_api64.dll.test",
                    STEAM_API64_DIFF,
                    SHA256_OLD_STEAM_API64_DLL
                    )?;
            },
            _ => {
                println!("Unidentified steam_api.dll??");
            }
        }
    }
    
    
    Ok(())
}

fn revert<T : AsRef<Path> + Display>(src_buff : Vec<u8>, dst : T, diff_buff : &[u8], result_hash : &[u8])
    -> Result<(), Box<dyn std::error::Error>>
{
    let out_filesize = diff_buff.len();
    let mut out_buff =  Vec::with_capacity(out_filesize);
    
    for (src_byte, diff_byte) in (&src_buff).into_iter().zip(diff_buff) {
        out_buff.push(diff_byte.wrapping_add(*src_byte));
    }
    
    if diff_buff.len() > src_buff.len()
    {
        let end_part = &diff_buff[src_buff.len() ..];
        
        for diff_byte in end_part {
            out_buff.push(*diff_byte);
        }
    }
    
    // let's verify our result
    let hash = Sha256::digest(&out_buff);
    let hash : &[u8] = hash.as_slice();
    let hash = array_of_bytes_to_text(hash);
    
    if hash == result_hash {
        let pretty_hash = String::from_utf8(hash)?;
        println!("reverting success with hash {pretty_hash}\nwriting to {dst}");
    } else {
        let pretty_result_hash = String::from_utf8(result_hash.to_vec())?;
        let pretty_hash = String::from_utf8(hash)?;
        println!("resulted in incorrect hash {pretty_result_hash}, should be {pretty_hash}");
    }
    
    fs::write(dst, out_buff)?;
    
    Ok(())
}

fn create_diff<T: AsRef<Path>, T2 : AsRef<Path>, T3 : AsRef<Path>>(old : T, new : T2, diff : T3)
    -> Result<(), Box<dyn std::error::Error>>
{
    let old_filesize = get_filesize(&old)?;
    
    let old_buff : Vec<u8> = fs::read(old)?;
    let new_buff : Vec<u8> = fs::read(new)?;
    
    let mut diff_buff = Vec::with_capacity(old_filesize);
    
    for (old_byte, new_byte) in (&old_buff).into_iter().zip(&new_buff) {
        diff_buff.push(old_byte.wrapping_sub(*new_byte));
    }
    
    if old_buff.len() > new_buff.len()
    {
        let end_part = &old_buff[new_buff.len() ..];
        
        for byte in end_part {
            diff_buff.push(*byte);
        }
    }
    
    fs::write(diff, diff_buff)?;
    
    Ok(())
}