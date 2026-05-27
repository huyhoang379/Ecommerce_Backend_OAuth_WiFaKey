// src/auth/entities/user.entity.ts
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  @Index('IDX_USER_IDP_USER_ID')
  idpUserId: string; // 'sub' claim từ IdP

  @Column({ unique: true, nullable: true })
  @Index('IDX_USER_EMAIL')
  email?: string;

  @Column({ nullable: true })
  name: string;

  @Column({ nullable: true })
  nickname: string;

  @Column({ nullable: true })
  phone: string;

  @Column({ nullable: true })
  gender: string; // male | female | other

  @Column({ nullable: true })
  picture: string;

  @Column({ type: 'varchar', nullable: true })
  membershipLevel: string;

  // Metadata - KHÔNG lưu token
  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  lastLogoutAt: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Optional: User preferences
  @Column({ type: 'jsonb', nullable: true, default: {} })
  preferences: Record<string, any>;

  // Optional: User roles
  @Column({ type: 'simple-array', default: [] })
  roles: string[];
}
