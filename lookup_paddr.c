#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/pgtable_types.h>

#define INVALID_ADDR 0x5555555555555555

unsigned long virtaddr_to_physaddr(struct mm_struct *mm, unsigned long vaddr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long paddr = 0;

    pgd = pgd_offset(mm, vaddr);
    printk("pgd_val = 0x%lx\n", pgd_val(*pgd));
    printk("pgd_index = %lu\n", pgd_index(vaddr));
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return INVALID_ADDR;
    }

    pud = pud_offset(pgd, vaddr);
    printk("pud_val = 0x%lx\n", pud_val(*pud));
    printk("pud_index = %lu\n", pud_index(vaddr));
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return INVALID_ADDR;
    }

    pmd = pmd_offset(pud, vaddr);
    printk("pmd_val = 0x%lx\n", pmd_val(*pmd));
    printk("pmd_index = %lx\n", pmd_index(vaddr));
    if(pmd_none(*pmd)){
        printk("not mapped in pmd\n");
        return INVALID_ADDR;
    }
    /*If pmd_large is true, represent pmd is the last level*/
    if(pmd_large(*pmd)){
        paddr = (pmd_val(*pmd) & PAGE_MASK);
        paddr = paddr | (vaddr & ~PAGE_MASK);
        return paddr;
    }
    /*Walk the forth level page table
    ** you may use PAGE_MASK = 0xfffffffffffff000 to help you get [0:11] bits
    ***/
    else{
        /*Need to implement*/
        /*...................*/
		pte = pte_offset_kernel(pmd,vaddr);
		printk("pte_val = 0x%lx\n",pte_val(*pte));
		printk("pte_index = %lx\n",pte_index(vaddr));
		if(pte_none(*pte)){
			printk("not mapped in pte\n");
			return INVALID_ADDR;
		}
		paddr = (pte_val(*pte) & PAGE_MASK);
		paddr = paddr | (vaddr & ~PAGE_MASK);
		printk("paddr = %lx\n", paddr);
        /*...................*/
        /*End of implement*/
        return paddr;
    }

}


asmlinkage unsigned long sys_lookup_paddr(pid_t pid, unsigned long vaddr)
{
    struct task_struct *p;
    unsigned long ret = INVALID_ADDR;

    p = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (p == NULL)
    {
        printk("Wrong pid: %d\n", pid);
        return ret;
    }

    ret = virtaddr_to_physaddr(p->mm, vaddr);

    return ret;
}
