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

- The `instruction` attribute before the `derive` attribute on all of the structs. This is currently a warning but will be a hard error in future releases. More on this [here.](https://github.com/rust-lang/rust/issues/79202)

- The `signer` accounts in all of the structs don't have a check implemented if they are signers or not. To do this the `signer` should be of type `Signer` and not of type `AccountInfo`. The `Signer` type extends the `AccountInfo` type and implements a check if the account is actually a signer.

- The `sender` and `reciever` accounts should be mutable in the `TransferPoints` struct to allow the changes to be persisted.

- The `sender` account in the `TransferPoints` struct should have a constraint that checks if the signer public key is equal to the sender's owner public key otherwise anyone could transfer points from the sender.

- The `user` account in the `RemoveUser` struct is not mutable and doesn't have a `close` constraint so the `user` account cannot be closed when calling the `remove_user` instruction.

- The `user` account in the `RemoveUser` struct should have a constraint that checks if the signer public key is equal to the user's owner public key otherwise anyone could close the account.

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
        constraint = signer.key == &sender.owner,
        seeds = [b"user", id_sender.to_le_bytes().as_ref()],
        bump,
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
        mut,
        constraint = signer.key == &user.owner,
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

#### Initialize instruction

- Since the size of the name is restricted in the `init` constraint in the `CreateUser` struct to 10, there should be a check for the length of the name passed to the `initialize` instruction.

Before:

```rs
pub fn initialize(ctx: Context<CreateUser>, id: u32, name: String) -> Result<()> {
    let user = &mut ctx.accounts.user;
    user.id = id;
    user.owner = *ctx.accounts.signer.key;
    user.name = name;
    user.points = 1000;
    msg!("Created new user with 1000 points and id: {}", id);
    Ok(())
}
```

After:

```rs
const MAX_NAME_LENGTH: usize = 10;

pub fn initialize(ctx: Context<CreateUser>, id: u32, name: String) -> Result<()> {
    let user = &mut ctx.accounts.user;

    if name.len() > MAX_NAME_LENGTH {
        return err!(MyError::NameTooLong);
    }

    user.id = id;
    user.owner = *ctx.accounts.signer.key;
    user.name = name;
    user.points = 1000;

    msg!("Created new user with 1000 points and id: {}", id);

    Ok(())
}
```

#### Transfer points instruction

- There should be a check to see if the `amount` is greater than 0 so that only valid amounts of points are transfered.

- The arithmetic should be done using `checked_add` and `checked_sub` functions to insure there are no overflows or underflows.

- There should be a check to see if the `reciever` account exists before transfering points to it.

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

    if amount <= 0 {
        return err!(MyError::InvalidTransferAmount);
    }

    if receiver.owner == Pubkey::default() {
        return err!(MyError::AccountDoesNotExist);
    }

    if sender.points < amount {
        return err!(MyError::NotEnoughPoints);
    }

    sender.points = sender
        .points
        .checked_sub(amount)
        .ok_or(MyError::Underflow)?;

    receiver.points = sender
        .points
        .checked_add(amount)
        .ok_or(MyError::Overflow)?;

    msg!("Transferred {} points", amount);
    Ok(())
}
```

#### Remove user instruction

- The instruction uses the wrong struct and it will most likely cause a transaction error when called. The `TransferPoints` struct should be replaced with the `RemoveUser` struct.
- There should be a check to seee if the `user` account exists before deleting it.

Before

```rs
pub fn remove_user(_ctx: Context<TransferPoints>, id: u32) -> Result<()> {
    msg!("Account closed for user with id: {}", id);
    Ok(())
}
```

After

```rs
pub fn remove_user(ctx: Context<RemoveUser>, id: u32) -> Result<()> {
    let user: &Account<User> = &ctx.accounts.user;

    if user.owner == Pubkey::default() {
        return err!(MyError::AccountDoesNotExist);
    }

    msg!("Account closed for user with id: {}", id);

    Ok(())
}
```

## Fixed program

```rs title=lib.rs
use anchor_lang::prelude::*;

declare_id!("6L2Rzxs71PiAxUmUxaNTT2Q3mnQjiJ8DwWiV1UxKa7Ph");

const MAX_NAME_LENGTH: usize = 10;
const PDA_USER_SEED: &[u8; 4] = b"user";

#[program]
pub mod secure_program {
    use super::*;

    pub fn initialize(ctx: Context<CreateUser>, id: u32, name: String) -> Result<()> {
        let user: &mut Account<User> = &mut ctx.accounts.user;

        if name.len() > MAX_NAME_LENGTH {
            return err!(MyError::NameTooLong);
        }

        user.id = id;
        user.owner = *ctx.accounts.signer.key;
        user.name = name;
        user.points = 1000;

        msg!("Created new user with 1000 points and id: {}", id);

        Ok(())
    }

    pub fn transfer_points(
        ctx: Context<TransferPoints>,
        _id_sender: u32,
        _id_receiver: u32,
        amount: u16,
    ) -> Result<()> {
        let sender: &mut Account<User> = &mut ctx.accounts.sender;
        let receiver: &mut Account<User> = &mut ctx.accounts.receiver;

        if amount <= 0 {
            return err!(MyError::InvalidTransferAmount);
        }

        if receiver.owner == Pubkey::default() {
            return err!(MyError::AccountDoesNotExist);
        }

        if sender.points < amount {
            return err!(MyError::NotEnoughPoints);
        }

        sender.points = sender
            .points
            .checked_sub(amount)
            .ok_or(MyError::Underflow)?;

        receiver.points = receiver
            .points
            .checked_add(amount)
            .ok_or(MyError::Overflow)?;

        msg!("Transferred {} points", amount);

        Ok(())
    }

    pub fn remove_user(ctx: Context<RemoveUser>, id: u32) -> Result<()> {
        let user_account: &Account<User> = &ctx.accounts.user;

        if user_account.owner == Pubkey::default() {
            return err!(MyError::AccountDoesNotExist);
        }

        msg!("Account closed for user with id: {}", id);

        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(id: u32)]
pub struct CreateUser<'info> {
    #[account(
        init,
        payer = signer,
        space = 8 + 4 + 32 + (4 + 10) + 2,
        seeds = [PDA_USER_SEED, id.to_le_bytes().as_ref()],
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
        constraint = signer.key == &sender.owner,
        seeds = [PDA_USER_SEED, id_sender.to_le_bytes().as_ref()],
        bump,
    )]
    pub sender: Account<'info, User>,

    #[account(
        mut,
        seeds = [PDA_USER_SEED, id_receiver.to_le_bytes().as_ref()],
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
        mut,
        constraint = signer.key == &user.owner,
        close = signer,
        seeds = [PDA_USER_SEED, id.to_le_bytes().as_ref()],
        bump
    )]
    pub user: Account<'info, User>,

    #[account(mut)]
    pub signer: Signer<'info>,

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
    NotEnoughPoints,
    #[msg("Cannot transfer zero or less than zero points")]
    InvalidTransferAmount,
    #[msg("Arithmetic overflow occured when adding points")]
    Overflow,
    #[msg("Arithmetic underflow occured when subtracting points")]
    Underflow,
    #[msg("Name is too long")]
    NameTooLong,
    #[msg("User account does not exist")]
    AccountDoesNotExist,
}
```
