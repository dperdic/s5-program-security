# S5 - Program Security

Fifth assignment for the Solana Summer Fellowship 2024.

## Assignment

### Description

```txt
Write about the issues and how to fix them in the Anchor program below.
```

### Insecure code

```rs title="lib.rs"
use anchor_lang::prelude::*;
declare_id!("6L2Rzxs71PiAxUmUxaNTT2Q3mnQjiJ8DwWiV1UxKa7Ph");

#[program]
pub mod unsecure_program {
    use super::*;

    pub fn initialize(ctx: Context<CreateUser>, id: u32, name: String) -> Result<()> {
        let user = &mut ctx.accounts.user;
        user.id = id;
        user.owner = *ctx.accounts.signer.key;
        user.name = name;
        user.points = 1000;
        msg!("Created new user with 1000 points and id: {}", id);
        Ok(())
    }

    pub fn transfer_points(ctx: Context<TransferPoints>, _id_sender:u32, _id_receiver:u32, amount: u16) -> Result<()> {
        let sender = &mut ctx.accounts.sender;
        let receiver = &mut ctx.accounts.receiver;

        if sender.points < amount {
            return err!(MyError::NotEnoughPoints);
        }
        sender.points -= amount;
        receiver.points += amount;
        msg!("Transferred {} points", amount);
        Ok(())
    }

    pub fn remove_user(_ctx: Context<TransferPoints>, id:u32) -> Result<()> {
        msg!("Account closed for user with id: {}", id);
        Ok(())
    }
}


#[instruction(id: u32)]
#[derive(Accounts)]
pub struct CreateUser<'info> {
    #[account(
        init,
        payer = signer,
        space = 8 + 4 + 32 + (4 + 10) + 2,
        seeds = [b"user", id.to_le_bytes().as_ref()],
        bump
    )]
    pub user: Account<'info, User>,

    #[account(mut)]
    pub signer: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}


#[instruction(id_sender: u32, id_receiver: u32)]
#[derive(Accounts)]
pub struct TransferPoints<'info> {
    #[account(
        seeds = [b"user", id_sender.to_le_bytes().as_ref()],
        bump
    )]
    pub sender: Account<'info, User>,
    #[account(
        seeds = [b"user", id_receiver.to_le_bytes().as_ref()],
        bump
    )]
    pub receiver: Account<'info, User>,
    #[account(mut)]
    pub signer: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[instruction(id: u32)]
#[derive(Accounts)]
pub struct RemoveUser<'info> {
    #[account(
        seeds = [b"user", id.to_le_bytes().as_ref()],
        bump
    )]
    pub user: Account<'info, User>,
    #[account(mut)]
    pub signer: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
#[derive(Default)]
pub struct User {
    pub id: u32,
    pub owner: Pubkey,
    pub name: String,
    pub points: u16,
}

#[error_code]
pub enum MyError {
    #[msg("Not enough points to transfer")]
    NotEnoughPoints
}
```

## Solution

### Issues

#### Struct issues

The structs have multiple issues.

- First issue is the `instruction` attribute before the `derive` attribute on all of the structs. This is currently a warning but will be a hard error in future releases. More on this [here.](https://github.com/rust-lang/rust/issues/79202)

- The `signer` accounts for don't have a check implemented if they are signers or not. To do this the `signer` should be of type `Signer` and not of type `AccountInfo`. The `Signer` type extends the `AccountInfo` type and implements a check if the account is actually a signer.

- The `user` account has insuficient space. The size of the user struct is 64 but the sum of the space currently provisioned is 59. An easier way to calculate the space would be to use the `size_of` function and 8.

- The `sender` and `reciever` accounts should be mutable in the `TransferPoints` struct to allow the changes in the amount to be persisted.

- The `sender` account should have a signer constraint so that only the sender can transfer the points to the reciever

- The `user` account in the `RemoveUser` struct is not mutable and doesn't have a `close` constraint so the `user` account cannot be closed when calling the `remove_user` instruction

Before:

```rs
#[instruction(id: u32)]
#[derive(Accounts)]
pub struct CreateUser<'info> {
    #[account(
        init,
        payer = signer,
        space = 8 + 4 + 32 + (4 + 10) + 2,
        seeds = [b"user", id.to_le_bytes().as_ref()],
        bump
    )]
    pub user: Account<'info, User>,

    #[account(mut)]
    pub signer: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[instruction(id_sender: u32, id_receiver: u32)]
#[derive(Accounts)]
pub struct TransferPoints<'info> {
    #[account(
        seeds = [b"user", id_sender.to_le_bytes().as_ref()],
        bump
    )]
    pub sender: Account<'info, User>,

    #[account(
        seeds = [b"user", id_receiver.to_le_bytes().as_ref()],
        bump
    )]
    pub receiver: Account<'info, User>,

    #[account(mut)]
    pub signer: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[instruction(id: u32)]
#[derive(Accounts)]
pub struct RemoveUser<'info> {
    #[account(
        seeds = [b"user", id.to_le_bytes().as_ref()],
        bump
    )]
    pub user: Account<'info, User>,

    #[account(mut)]
    pub signer: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}
```

After:

```rs
#[derive(Accounts)]
#[instruction(id: u32)]
pub struct CreateUser<'info> {
    #[account(
        init,
        payer = signer,
        space = size_of::<User>() + 8,
        seeds = [b"user", id.to_le_bytes().as_ref()],
        bump
    )]
    pub user: Account<'info, User>,

    #[account(mut)]
    pub signer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(id_sender: u32, id_receiver: u32)]
pub struct TransferPoints<'info> {
    #[account(
        mut,
        signer,
        seeds = [b"user", id_sender.to_le_bytes().as_ref()],
        bump
    )]
    pub sender: Account<'info, User>,

    #[account(
        mut,
        seeds = [b"user", id_receiver.to_le_bytes().as_ref()],
        bump
    )]
    pub receiver: Account<'info, User>,

    #[account(mut)]
    pub signer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(id: u32)]
pub struct RemoveUser<'info> {
    #[account(
        close = signer,
        seeds = [b"user", id.to_le_bytes().as_ref()],
        bump
    )]
    pub user: Account<'info, User>,

    #[account(mut)]
    pub signer: Signer<'info>,

    pub system_program: Program<'info, System>,
}
```

#### Transfer points instruction

There should be a check to see if the reciever pda exists before allocating points. If it doesn't exist the transaction will fail.

The arithmetic should be done using `checked_add` and `checked_sub` functions to insure there are no overflows or underflows

Before:

```rs
pub fn transfer_points(
    ctx: Context<TransferPoints>,
    _id_sender: u32,
    _id_receiver: u32,
    amount: u16,
) -> Result<()> {
    let sender = &mut ctx.accounts.sender;
    let receiver = &mut ctx.accounts.receiver;

    if sender.points < amount {
        return err!(MyError::NotEnoughPoints);
    }

    sender.points -= amount;
    receiver.points += amount;

    msg!("Transferred {} points", amount);
    Ok(())
}
```

After:

```rs
pub fn transfer_points(
    ctx: Context<TransferPoints>,
    _id_sender: u32,
    _id_receiver: u32,
    amount: u16,
) -> Result<()> {
    let sender = &mut ctx.accounts.sender;
    let receiver = &mut ctx.accounts.receiver;

    if sender.points < amount {
        return err!(MyError::NotEnoughPoints);
    }

    sender.points = sender
        .points
        .checked_sub(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    receiver.points = sender
        .points
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    msg!("Transferred {} points", amount);
    Ok(())
}
```

#### Remove user instruction

The instruction user the wrong struct and it will most likely cause a transaction error when called. The `TransferPoints` struct should be replaced with the `RemoveUser` struct.

Before

```rs
pub fn remove_user(_ctx: Context<TransferPoints>, id: u32) -> Result<()> {
    msg!("Account closed for user with id: {}", id);
    Ok(())
}
```

After

```rs
pub fn remove_user(_ctx: Context<RemoveUser>, id: u32) -> Result<()> {
    msg!("Account closed for user with id: {}", id);
    Ok(())
}
```
