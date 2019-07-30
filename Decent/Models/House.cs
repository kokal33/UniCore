using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Decent.Models
{
    public class House
    {
        [Key]
        public long Id { get; set; }
        public string Name { get; set; }
        public int Beds { get; set; }
        public List<Chores> Chores { get; set; }
        public List<string> Rules { get; set; }
    }
}
